const $ = id => document.getElementById(id);
let config = {}, lastJob = null, polling = false, showLogs = false;
let checkingConnection = false;
const labels = {running:'Scan running',done:'Scan completed',failed:'Scan failed',cancelled:'Scan cancelled',interrupted:'Scan interrupted by service restart',timeout:'Time limit exceeded',limit:'Output size limit exceeded'};
function message(text) { $('message').textContent = text; }
function connection(state, text) {
  $('connection-status').dataset.state = state;
  $('connection-status').title = config.serverUrl || 'Configure the server URL and API key.';
  const icon = {idle:'●',checking:'◌',online:'✓',error:'!'}[state];
  if ($('connection-icon').textContent !== icon) $('connection-icon').textContent = icon;
  if ($('connection-label').textContent !== text) $('connection-label').textContent = text;
}
async function checkConnection() {
  if (checkingConnection) return;
  if (!config.token || !config.serverUrl) {
    connection('idle', 'Configure connection');
    return;
  }
  checkingConnection = true;
  $('check-connection').disabled = true;
  connection('checking', 'Checking connection…');
  try {
    const health = await api('/api/health');
    if (health?.ok !== true) {
      connection('error', 'Invalid API response');
      throw new Error('The server did not return a valid API status. Check its URL.');
    }
  } finally {
    checkingConnection = false;
    $('check-connection').disabled = false;
  }
}
$('check-connection').addEventListener('click', async () => {
  try { await checkConnection(); }
  catch (error) { message(error.message); }
});
function readRateLimit() {
  const raw = String($('rate-limit').value).trim(), value = Number(raw);
  if (!raw || !Number.isInteger(value) || value < 0 || value > 2147483647) throw new Error('The rate limit must be an integer from 0 to 2147483647. Use 0 for unlimited requests.');
  return value;
}
$('rate-limit').addEventListener('change', async () => {
  try { await chrome.storage.local.set({scanRateLimit:readRateLimit()}); }
  catch (error) { message(error.message); }
});
async function refreshHistory() {
  const {jobs} = await api('/api/jobs');
  $('history').replaceChildren();
  $('history-label').hidden = !jobs.length;
  for (const job of jobs) {
    const option = document.createElement('option'); option.value = job.id;
    option.textContent = `${labels[job.status] || job.status} · ${job.target}`;
    $('history').append(option);
  }
  const active = jobs.find(job => job.status === 'running');
  if (active) lastJob = active.id;
  else if (!jobs.some(job => job.id === lastJob)) lastJob = jobs[0]?.id || null;
  if (lastJob) {
    $('history').value = lastJob;
    await chrome.storage.local.set({lastJob});
    await showJob();
  }
  else message('Connected. Enter a target URL and select a scan profile.');
}
async function api(path, options = {}) {
  if (!config.token || !config.serverUrl) {
    connection('idle', 'Configure connection');
    throw new Error('Save the server URL and API key in connection settings.');
  }
  let response;
  try {
    response = await fetch(`${config.serverUrl}${path}`, {
      ...options, cache:'no-store', redirect:'error', credentials:'omit',
      headers:{'Authorization':`Bearer ${config.token}`,'Content-Type':'application/json'},
      signal:AbortSignal.timeout(10000)
    });
  } catch {
    connection('error', 'Disconnected');
    throw new Error('Connection failed. Check the server URL, port, firewall, HTTPS certificate, and extension host permission.');
  }
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) connection('error', 'Authentication failed');
    else if (response.status === 429) connection('error', 'API rate limit reached');
    else if (response.status >= 500) connection('error', 'Server error');
    else if (path === '/api/health') connection('error', 'Invalid API URL');
    else connection('online', 'Connected to server');
    const body = await response.json().catch(() => ({}));
    const id = response.headers?.get('X-Request-ID');
    throw new Error((body.error || `HTTP error ${response.status}`) + (id ? ` [request: ${id}]` : ''));
  }
  let data;
  try { data = await (/\/(output|log)$/.test(path) ? response.text() : response.json()); }
  catch {
    connection('error', 'Invalid API response');
    throw new Error('Unable to read the server response. Check the API URL.');
  }
  connection('online', 'Connected to server');
  return data;
}
async function showJob() {
  if (!lastJob || polling) return;
  polling = true;
  try {
    const job = await api(`/api/jobs/${lastJob}`);
    message(`${labels[job.status] || job.status}${job.error ? ': '+job.error : ''}`);
    const rate = job.rate_limit ?? 5;
    $('job').textContent = `${job.target}\nID: ${job.id}\nLimit: ${rate === 0 ? 'unlimited' : rate + ' requests/s'}\nServer output file: ${job.output_file}`;
    $('job').style.whiteSpace = 'pre-wrap';
    $('download').disabled = job.status === 'running';
    $('cancel').disabled = job.status !== 'running';
    $('start').disabled = job.status === 'running';
    $('logs').disabled = false;
    if (showLogs) $('scan-log').textContent = await api(`/api/jobs/${lastJob}/log`);
  } catch (error) { message(error.message); }
  finally { polling = false; }
}
$('save').addEventListener('click', async () => {
  try {
    const url = new URL($('server-url').value.trim()), token = $('token').value.trim();
    if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Enter a server origin such as http://203.0.113.10:8765, without a path or credentials.');
    if (token.length < 32) throw new Error('The API key must contain at least 32 characters.');
    // Request host access only as a direct consequence of this button click.
    const granted = await chrome.permissions.request({origins:[`${url.protocol}//${url.hostname}/*`]});
    if (!granted) throw new Error('Permission to access this server was not granted.');
    config = {serverUrl:url.origin, token};
    lastJob = null; showLogs = false;
    $('scan-log').hidden = true; $('preview').hidden = true;
    $('job').textContent = ''; $('download').disabled = true; $('cancel').disabled = true;
    $('logs').disabled = true; $('start').disabled = false;
    $('logs').textContent = 'Show Nuclei log';
    await chrome.storage.local.set({config,lastJob});
    await checkConnection(); await refreshHistory(); message('Connected to server.');
  } catch (error) { message(error.message); }
});
$('current').addEventListener('click', async () => {
  const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
  if (tab?.url && /^https?:\/\//.test(tab.url)) $('target').value = tab.url.split('#')[0];
  else message('Open an HTTP or HTTPS page.');
});
$('start').addEventListener('click', async () => {
  $('start').disabled = true;
  try {
    const target = new URL($('target').value);
    if (!['http:','https:'].includes(target.protocol)) throw new Error('Enter an HTTP or HTTPS URL.');
    const rateLimit = readRateLimit();
    await chrome.storage.local.set({scanRateLimit:rateLimit});
    const job = await api('/api/jobs', {method:'POST',body:JSON.stringify({target:target.href,profile:$('profile').value,rate_limit:rateLimit})});
    lastJob = job.id;
    await chrome.storage.local.set({lastJob});
    $('preview').hidden = true;
    $('scan-log').textContent = '';
    $('download').disabled = true;
    await refreshHistory();
  } catch (error) { message(error.message); $('start').disabled = false; }
});
$('history').addEventListener('change', async () => {
  lastJob = $('history').value;
  $('preview').hidden = true;
  $('scan-log').textContent = '';
  await chrome.storage.local.set({lastJob});
  await showJob();
});
$('cancel').addEventListener('click', async () => {
  if (!lastJob) return;
  try { await api(`/api/jobs/${lastJob}/cancel`, {method:'POST',body:'{}'}); await showJob(); }
  catch (error) { message(error.message); }
});
$('download').addEventListener('click', async () => {
  if (!lastJob) return;
  try {
    const text = await api(`/api/jobs/${lastJob}/output`);
    $('preview').hidden = false;
    $('preview').textContent = text.slice(0,16000) || 'No findings in the file. Check the scan status: an empty result does not prove the target is secure.';
    const url = URL.createObjectURL(new Blob([text],{type:'text/plain;charset=utf-8'}));
    const link = document.createElement('a'); link.href = url; link.download = `nuclei-${lastJob}.txt`;
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 30000);
  } catch (error) { message(error.message); }
});
$('logs').addEventListener('click', async () => {
  showLogs = !showLogs;
  $('scan-log').hidden = !showLogs;
  $('logs').textContent = showLogs ? 'Hide Nuclei log' : 'Show Nuclei log';
  if (showLogs) await showJob();
});
(async () => {
  await chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
  const stored = await chrome.storage.local.get(['config','lastJob','scanRateLimit']);
  $('rate-limit').value = stored.scanRateLimit ?? 5;
  config = stored.config || {}; lastJob = stored.lastJob || null;
  if (!config.serverUrl && config.port) config.serverUrl = `http://127.0.0.1:${config.port}`;
  $('server-url').value = config.serverUrl || ''; $('token').value = config.token || '';
  $('settings').open = !config.token || !config.serverUrl;
  if (config.token && config.serverUrl) { try { await checkConnection(); await refreshHistory(); } catch (error) { $('settings').open = true; message(error.message); } }
  else connection('idle', 'Configure connection');
})();
setInterval(showJob, 2500);
// Health checks run only while the popup is open, including when there are no jobs.
setInterval(() => checkConnection().catch(() => {}), 15000);
