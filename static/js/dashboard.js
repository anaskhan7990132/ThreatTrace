'use strict';

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
const state = { summary: null, alerts: [], events: [], malformed: [], page: 1, pageSize: 100, totalFiltered: 0, activeView: 'overview', charts: {}, generatedAt: null };

function escapeText(value) { return String(value ?? '—'); }
function formatNumber(value) { return new Intl.NumberFormat().format(Number(value || 0)); }
function setStatus(message, kind = 'info') {
  const el = $('#status-message');
  if (!el) return;
  el.className = `notice-row ${kind === 'success' ? 'success' : kind === 'error' ? 'error' : ''}`;
  const icon = document.createElement('span'); icon.className = 'notice-icon'; icon.textContent = kind === 'success' ? '✓' : kind === 'error' ? '!' : 'i';
  const text = document.createElement('span'); text.textContent = message;
  el.replaceChildren(icon, text);
}
async function api(url, options = {}) {
  const response = await fetch(url, { cache: 'no-store', ...options });
  const contentType = response.headers.get('content-type') || '';
  let body;
  if (contentType.includes('application/json')) body = await response.json();
  else body = await response.text();
  if (!response.ok) throw new Error(body && body.error ? body.error : `Request failed (${response.status}).`);
  return body;
}
function navTo(view) {
  state.activeView = view;
  $$('.page-view').forEach(node => node.classList.toggle('active', node.id === `view-${view}`));
  $$('.nav-item').forEach(node => node.classList.toggle('active', node.dataset.view === view));
  const active = $(`.nav-item[data-view="${view}"]`);
  $('#view-breadcrumb').textContent = active ? active.textContent.trim().replace(/\s+\d+$/, '').toUpperCase() : view.toUpperCase();
  $('#sidebar').classList.remove('open');
  if (view === 'events') loadEvents();
  if (view === 'alerts') renderFullAlerts();
  if (view === 'reports') renderReportSnapshot();
}
function makeNode(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; }
function updateSummary(summary) {
  state.summary = summary || {};
  const values = {
    '#metric-total': summary.total_events, '#metric-success': summary.successful_logins,
    '#metric-failed': summary.failed_logins, '#metric-ips': summary.unique_source_ips,
    '#metric-suspicious': summary.suspicious_activity,
    '#nav-event-count': summary.total_events, '#nav-alert-count': summary.alert_count,
    '#report-events': summary.total_events, '#report-alerts': summary.alert_count, '#report-malformed': summary.malformed_lines,
  };
  Object.entries(values).forEach(([selector, value]) => { const node = $(selector); if (node) node.textContent = formatNumber(value); });
  $('#metric-alert-count').textContent = `${formatNumber(summary.alert_count)} alerts`;
  $('#alerts-total').textContent = formatNumber(summary.alert_count);
  renderSeverity(summary.severity_counts || {});
  drawCharts(summary);
}
async function updateAnalysis(result) {
  state.alerts = result.alerts || [];
  state.events = result.events || [];
  state.malformed = result.malformed || [];
  state.generatedAt = result.generated_at || null;
  updateSummary(result.summary || {});
  $('#generated-at').textContent = state.generatedAt ? `GENERATED ${state.generatedAt}` : 'NO ANALYSIS LOADED';
  $('#current-date').textContent = state.generatedAt ? `UPDATED ${state.generatedAt}` : 'READY FOR ANALYSIS';
  $('#report-time').textContent = state.generatedAt || '—';
  $('#rule-threshold').value = (result.settings && result.settings.failure_threshold) || 5;
  $('#rule-window').value = (result.settings && result.settings.window_minutes) || 10;
  $('#nav-event-count').textContent = formatNumber(state.events.length);
  $('#nav-alert-count').textContent = formatNumber(state.alerts.length);
  renderAlertsPreview(); renderFullAlerts(); renderReportSnapshot();
  state.page = 1; await loadEvents();
}
function renderSeverity(counts) {
  const container = $('#severity-bars');
  const values = [
    ['High', counts.high || 0, 'high'], ['Medium', counts.medium || 0, 'medium'],
    ['Low', counts.low || 0, 'low'], ['Info', counts.info || 0, 'info'],
  ];
  const total = values.reduce((sum, item) => sum + item[1], 0);
  if (!total) { container.replaceChildren(makeEmpty('◉', 'Waiting for event data', 'Load a log to populate severity counts.', true)); return; }
  container.replaceChildren();
  values.forEach(([label, count, cls]) => {
    const row = makeNode('div', 'severity-row');
    row.append(makeNode('span', '', label));
    const track = makeNode('div', 'severity-track');
    const fill = makeNode('div', `severity-fill ${cls}`); fill.style.width = `${Math.max(0, Math.min(100, count / total * 100))}%`; track.append(fill);
    row.append(track, makeNode('span', 'severity-number', formatNumber(count))); container.append(row);
  });
}
function makeEmpty(icon, title, subtitle, compact = false) {
  const el = makeNode('div', `empty-state${compact ? ' compact' : ''}`);
  el.append(makeNode('span', '', icon), makeNode('strong', '', title), makeNode('p', '', subtitle));
  return el;
}
function renderAlertsPreview() {
  const container = $('#alert-preview'); container.replaceChildren();
  if (!state.alerts.length) { container.append(makeEmpty('⌁', 'No alerts to display', 'Analyze logs to discover potential patterns.', true)); return; }
  state.alerts.slice(0, 3).forEach(alert => container.append(alertRow(alert)));
}
function alertRow(alert) {
  const row = makeNode('div', 'alert-row');
  row.append(makeNode('div', 'alert-row-mark'));
  const copy = makeNode('div', '');
  copy.append(makeNode('div', 'alert-row-title', `Possible brute force · ${alert.source_ip}`));
  copy.append(makeNode('div', 'alert-row-sub', `${alert.failure_count} flagged failures · ${alert.window_minutes} min window`));
  const pill = makeNode('span', 'severity-pill high', String(alert.severity || 'high').toUpperCase());
  row.append(copy, pill); return row;
}
function renderFullAlerts() {
  const container = $('#alerts-list'); if (!container) return;
  container.replaceChildren();
  $('#alerts-total').textContent = formatNumber(state.alerts.length);
  if (!state.alerts.length) { container.append(makeEmpty('⌁', 'No suspicious patterns detected', 'Load sample data or analyze an authorized authentication log.')); return; }
  state.alerts.forEach(alert => {
    const card = makeNode('article', 'full-alert-card');
    const copy = makeNode('div', '');
    copy.append(makeNode('div', 'alert-ip', alert.source_ip));
    copy.append(makeNode('h3', '', 'Possible SSH brute-force activity'));
    copy.append(makeNode('p', '', alert.explanation));
    const meta = makeNode('div', 'alert-meta');
    [`${alert.failure_count} flagged failures`, `Peak window: ${alert.peak_window_count}`, `${alert.threshold}+ threshold`, `${alert.window_minutes} minute window`, `First: ${alert.first_seen}`, `Last: ${alert.last_seen}`].forEach(value => meta.append(makeNode('span', '', value)));
    copy.append(meta);
    card.append(copy, makeNode('span', 'severity-pill high', String(alert.severity || 'high').toUpperCase()));
    container.append(card);
  });
}
function renderReportSnapshot() {
  const summary = state.summary || {};
  $('#report-events').textContent = formatNumber(summary.total_events);
  $('#report-alerts').textContent = formatNumber(summary.alert_count);
  $('#report-malformed').textContent = formatNumber(summary.malformed_lines);
  $('#report-time').textContent = state.generatedAt || '—';
  const preview = $('#malformed-preview'); preview.replaceChildren();
  if (!state.malformed.length) return;
  preview.append(makeNode('div', 'summary-kicker', 'PARSER DIAGNOSTICS (FIRST 10)'));
  state.malformed.slice(0, 10).forEach(issue => {
    const row = makeNode('div', 'malformed-item'); row.append(makeNode('code', '', `Line ${issue.line}`), makeNode('span', '', issue.reason)); preview.append(row);
  });
}
function drawCharts(summary) {
  const timeline = summary.timeline || []; const ips = summary.failed_by_ip || [];
  $('#timeline-empty').style.display = timeline.length ? 'none' : 'flex';
  $('#ip-empty').style.display = ips.length ? 'none' : 'flex';
  drawTimeline(timeline); drawIpBars(ips);
}
function chartColors() { return { grid: 'rgba(130,151,178,.12)', labels: '#71839a', cyan: '#38d7f2', red: '#ff647c' }; }
function destroyChart(id) { if (state.charts[id] && typeof state.charts[id].destroy === 'function') state.charts[id].destroy(); delete state.charts[id]; }
function drawTimeline(rows) {
  const canvas = $('#timeline-chart'); destroyChart('timeline');
  const colors = chartColors(); const labels = rows.map(row => row.timestamp.slice(5, 16).replace('T', ' '));
  if (window.Chart && rows.length) {
    state.charts.timeline = new Chart(canvas, { type: 'line', data: { labels, datasets: [
      { label: 'Success', data: rows.map(row => row.success), borderColor: colors.cyan, backgroundColor: 'rgba(56,215,242,.09)', fill: true, tension: .35, pointRadius: 2, borderWidth: 2 },
      { label: 'Failed', data: rows.map(row => row.failed), borderColor: colors.red, backgroundColor: 'rgba(255,100,124,.04)', fill: false, tension: .35, pointRadius: 2, borderWidth: 2 },
    ] }, options: { maintainAspectRatio: false, responsive: true, interaction: { mode: 'index', intersect: false }, plugins: { legend: { display: false }, tooltip: { backgroundColor: '#111c2b', borderColor: '#34445a', borderWidth: 1, titleColor: '#dce8f6', bodyColor: '#a8b7ca' } }, scales: { x: { ticks: { color: colors.labels, maxTicksLimit: 6, font: { size: 9 } }, grid: { display: false }, border: { color: colors.grid } }, y: { beginAtZero: true, ticks: { color: colors.labels, precision: 0, font: { size: 9 } }, grid: { color: colors.grid }, border: { display: false } } } } }); return;
  }
  drawCanvasLine(canvas, rows, colors);
}
function drawCanvasLine(canvas, rows, colors) {
  const ctx = canvas.getContext('2d'); const rect = canvas.getBoundingClientRect(); const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, rect.width * dpr); canvas.height = Math.max(1, rect.height * dpr); ctx.scale(dpr, dpr);
  const w = rect.width, h = rect.height, pad = { left: 28, right: 8, top: 12, bottom: 30 }, innerW = w-pad.left-pad.right, innerH = h-pad.top-pad.bottom;
  ctx.clearRect(0,0,w,h); ctx.font = '9px DM Mono, monospace'; ctx.fillStyle = colors.labels; ctx.strokeStyle = colors.grid; ctx.lineWidth = 1;
  if (!rows.length) return;
  const max = Math.max(1, ...rows.map(r => Math.max(r.success, r.failed)));
  for(let g=0;g<=3;g++){const y=pad.top+innerH*g/3;ctx.beginPath();ctx.moveTo(pad.left,y);ctx.lineTo(w-pad.right,y);ctx.stroke();ctx.fillText(String(Math.round(max*(3-g)/3)),2,y+3);}
  [['success',colors.cyan],['failed',colors.red]].forEach(([key,color])=>{ctx.strokeStyle=color;ctx.lineWidth=2;ctx.beginPath();rows.forEach((r,i)=>{const x=pad.left+(rows.length===1?innerW/2:i*innerW/(rows.length-1));const y=pad.top+innerH-(r[key]/max)*innerH;if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);});ctx.stroke();rows.forEach((r,i)=>{const x=pad.left+(rows.length===1?innerW/2:i*innerW/(rows.length-1));const y=pad.top+innerH-(r[key]/max)*innerH;ctx.fillStyle=color;ctx.beginPath();ctx.arc(x,y,2.5,0,Math.PI*2);ctx.fill();});});
  const step=Math.max(1,Math.ceil(rows.length/4));rows.forEach((r,i)=>{if(i%step!==0&&i!==rows.length-1)return;const x=pad.left+(rows.length===1?innerW/2:i*innerW/(rows.length-1));ctx.fillStyle=colors.labels;ctx.fillText(r.timestamp.slice(11,16),Math.max(0,Math.min(w-32,x-13)),h-8);});
}
function drawIpBars(rows) {
  const canvas=$('#ip-chart');destroyChart('ip');const colors=chartColors();
  if(window.Chart&&rows.length){state.charts.ip=new Chart(canvas,{type:'bar',data:{labels:rows.map(r=>r.source_ip),datasets:[{label:'Failed attempts',data:rows.map(r=>r.count),backgroundColor:'rgba(255,100,124,.7)',borderColor:colors.red,borderWidth:1,borderRadius:3}]},options:{indexAxis:'y',maintainAspectRatio:false,responsive:true,plugins:{legend:{display:false},tooltip:{backgroundColor:'#111c2b',borderColor:'#34445a',borderWidth:1}},scales:{x:{beginAtZero:true,ticks:{color:colors.labels,precision:0,font:{size:9}},grid:{color:colors.grid},border:{display:false}},y:{ticks:{color:'#aab7c9',font:{size:9,family:'DM Mono'}},grid:{display:false},border:{display:false}}}}});return;}
  drawCanvasBars(canvas,rows,colors);
}
function drawCanvasBars(canvas,rows,colors){const ctx=canvas.getContext('2d');const rect=canvas.getBoundingClientRect();const dpr=window.devicePixelRatio||1;canvas.width=Math.max(1,rect.width*dpr);canvas.height=Math.max(1,rect.height*dpr);ctx.scale(dpr,dpr);const w=rect.width,h=rect.height;ctx.clearRect(0,0,w,h);if(!rows.length)return;const pad={left:15,right:23,top:7,bottom:7};const lineH=(h-pad.top-pad.bottom)/rows.length;const labelW=Math.min(125,Math.max(85,w*.34));const barX=labelW+pad.left;const barMax=Math.max(1,w-barX-pad.right);const max=Math.max(1,...rows.map(r=>r.count));ctx.font='9px DM Mono, monospace';rows.forEach((r,i)=>{const y=pad.top+i*lineH;ctx.fillStyle=colors.labels;let label=r.source_ip;if(label.length>18)label=label.slice(0,17)+'…';ctx.fillText(label,pad.left,y+lineH*.62);ctx.fillStyle='rgba(130,151,178,.1)';ctx.fillRect(barX,y+lineH*.22,barMax,Math.max(3,lineH*.48));const barW=Math.max(r.count?2:0,barMax*r.count/max);ctx.fillStyle=colors.red;ctx.fillRect(barX,y+lineH*.22,barW,Math.max(3,lineH*.48));ctx.fillStyle='#d4deeb';ctx.fillText(String(r.count),Math.min(w-14,barX+barW+5),y+lineH*.62);});}
function filtersToParams() {
  const params = new URLSearchParams();
  const fields = [['q', '#filter-q'], ['event_type', '#filter-type'], ['ip', '#filter-ip'], ['severity', '#filter-severity']];
  fields.forEach(([key, selector]) => { const val = $(selector).value.trim(); if (val) params.set(key, val); });
  const start = $('#filter-start').value, end = $('#filter-end').value;
  if(start) params.set('start', new Date(start).toISOString()); if(end) params.set('end', new Date(end).toISOString());
  params.set('page', String(state.page)); params.set('page_size', String(state.pageSize)); return params;
}
async function loadEvents() {
  try {
    const result = await api(`/api/events?${filtersToParams().toString()}`);
    state.totalFiltered = result.total || 0;
    renderEvents(result.events || []);
    $('#event-result-count').textContent = `${formatNumber(result.total)} event${result.total === 1 ? '' : 's'} found`;
    const start = result.total ? (result.page-1)*result.page_size+1 : 0; const end = Math.min(result.total, start + (result.events || []).length - 1);
    $('#event-page-info').textContent = `Showing ${formatNumber(start)}–${formatNumber(end)} of ${formatNumber(result.total)}`;
    $('#previous-page').disabled = state.page <= 1;
    $('#next-page').disabled = state.page*state.pageSize >= result.total;
  } catch (error) { setStatus(error.message, 'error'); }
}
function renderEvents(events) {
  const body = $('#event-table-body'); body.replaceChildren();
  if (!events.length) { const row=makeNode('tr');const cell=makeNode('td','table-empty','No matching events. Load sample logs or adjust filters.');cell.colSpan=6;row.append(cell);body.append(row);return; }
  events.forEach(event => {
    const row = makeNode('tr');
    row.append(makeNode('td','',event.timestamp));
    const eventCell=makeNode('td');const eventName=makeNode('span','event-name');eventName.append(makeNode('i',`event-kind-dot ${event.event_type==='success_login'?'success':'failed'}`),makeNode('span','',event.event_type==='success_login'?'Successful login':'Failed login'));eventCell.append(eventName);row.append(eventCell);
    row.append(makeNode('td','',event.username || 'unknown'));
    row.append(makeNode('td','ip-text',event.source_ip || '—'));
    row.append(makeNode('td','',event.host || '—'));
    const sev=makeNode('span',`severity-cell ${event.severity}`,event.severity);const sevCell=makeNode('td');sevCell.append(sev);row.append(sevCell);body.append(row);
  });
}
async function refreshAll() {
  const current = await api('/api/current');
  await updateAnalysis(current);
  if ((current.summary?.total_events || 0) === 0 && (current.summary?.malformed_lines || 0) === 0) {
    setStatus('Ready. Load synthetic sample logs or upload an authorized log file to begin.');
  } else {
    setStatus(`Restored current analysis: ${formatNumber(current.summary.total_events)} events and ${formatNumber(current.summary.alert_count)} alert(s).`, 'success');
  }
}

async function runSample(threshold, windowMinutes) {
  $('#sample-button').disabled=true;$('#sample-button').classList.add('uploading');
  try { const result=await api('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sample:true,threshold,window_minutes:windowMinutes})});await updateAnalysis(result);setStatus(`Synthetic sample analyzed: ${result.summary.total_events} events, ${result.summary.alert_count} alert(s), ${result.summary.malformed_lines} parser diagnostic(s).`, 'success'); }
  catch(error){setStatus(error.message,'error');}
  finally{$('#sample-button').disabled=false;$('#sample-button').classList.remove('uploading');}
}
$('#sample-button').addEventListener('click',()=>runSample(Number($('#rule-threshold').value)||5,Number($('#rule-window').value)||10));
$('#refresh-button').addEventListener('click',async()=>{try{await refreshAll();setStatus('Dashboard refreshed from the current backend analysis.','success');}catch(e){setStatus(e.message,'error');}});
$('#clear-button').addEventListener('click',async()=>{try{const result=await api('/api/clear',{method:'POST'});state.alerts=[];state.events=[];state.malformed=[];state.generatedAt=null;state.page=1;updateSummary(result.summary);$('#generated-at').textContent='NO ANALYSIS LOADED';$('#current-date').textContent='READY FOR ANALYSIS';$('#report-time').textContent='—';$('#file-name').textContent='No file selected';$('#log-file').value='';$('#analyze-button').disabled=true;renderAlertsPreview();renderFullAlerts();renderReportSnapshot();await loadEvents();setStatus('Current analysis results cleared from memory.','success');}catch(e){setStatus(e.message,'error');}});
$('#events-refresh').addEventListener('click',loadEvents);$('#alerts-refresh').addEventListener('click',async()=>{try{const r=await api('/api/alerts');state.alerts=r.alerts||[];renderFullAlerts();setStatus('Alerts refreshed.','success');}catch(e){setStatus(e.message,'error');}});
$('#mobile-menu').addEventListener('click',()=>$('#sidebar').classList.toggle('open'));
$$('.nav-item').forEach(button=>button.addEventListener('click',()=>navTo(button.dataset.view)));
$$('[data-go]').forEach(button=>button.addEventListener('click',()=>navTo(button.dataset.go)));
$('#log-file').addEventListener('change',()=>{const input=$('#log-file');const file=input.files&&input.files[0];$('#file-name').textContent=file?file.name:'No file selected';$('#analyze-button').disabled=!file;});
$('#upload-form').addEventListener('submit',async event=>{event.preventDefault();const file=$('#log-file').files[0];if(!file)return;if(file.size>5*1024*1024){setStatus('Selected file exceeds the 5 MB upload limit.','error');return;}const data=new FormData();data.append('file',file);data.append('threshold',$('#rule-threshold').value||'5');data.append('window_minutes',$('#rule-window').value||'10');$('#analyze-button').disabled=true;$('#upload-form').classList.add('uploading');
  try{const result=await api('/api/analyze',{method:'POST',body:data});await updateAnalysis(result);setStatus(`Analysis complete: ${result.summary.total_events} events parsed from ${file.name}. ${result.summary.malformed_lines} line(s) were skipped or malformed.`,'success');}catch(error){setStatus(error.message,'error');}finally{$('#analyze-button').disabled=false;$('#upload-form').classList.remove('uploading');}});
$('#filters-form').addEventListener('submit',event=>{event.preventDefault();state.page=1;loadEvents();});
$('#reset-filters').addEventListener('click',()=>{$('#filters-form').reset();state.page=1;loadEvents();});
$('#previous-page').addEventListener('click',()=>{if(state.page>1){state.page--;loadEvents();}});
$('#next-page').addEventListener('click',()=>{if(state.page*state.pageSize<state.totalFiltered){state.page++;loadEvents();}});
$('#rules-form').addEventListener('submit',event=>{event.preventDefault();const threshold=Number($('#rule-threshold').value);const windowMinutes=Number($('#rule-window').value);if(!Number.isInteger(threshold)||threshold<2||threshold>100||!Number.isInteger(windowMinutes)||windowMinutes<1||windowMinutes>1440){setStatus('Use a threshold from 2–100 and time window from 1–1440 minutes.','error');return;}navTo('overview');runSample(threshold,windowMinutes);});
$('#restore-rule-defaults').addEventListener('click',()=>{$('#rule-threshold').value=5;$('#rule-window').value=10;setStatus('Default rule restored: 5 failed logins within 10 minutes. Load or analyze logs to apply it.','success');});
$$('a[href^="/api/export/"]').forEach(link=>link.addEventListener('click',async event=>{ // Preserve normal download, but avoid exporting if no analysis exists.
  try{const stats=await api('/api/stats');if(stats.total_events===0&&stats.malformed_lines===0){event.preventDefault();setStatus('There is no analysis to export yet. Load sample logs or analyze a file first.','error');}}catch(_){event.preventDefault();setStatus('Could not contact the backend for export.','error');}
}));
window.addEventListener('resize',()=>{if(!window.Chart&&state.summary)drawCharts(state.summary);});
window.addEventListener('load',()=>{if(window.Chart&&state.summary)drawCharts(state.summary);});
(async function init(){
  try{const health=await api('/api/health');if(health.status!=='ok')throw new Error('The analysis engine did not report ready.');await refreshAll();}
  catch(error){setStatus(`Could not connect to the local API: ${error.message}. Start the Flask server and refresh this page.`,'error');}
})();
