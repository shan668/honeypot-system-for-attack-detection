{% extends "base.html" %}
{% block title %}Search &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="card">
    <h2>Unified Search</h2>
    <p class="muted">Search across sessions, alerts, credentials, commands and HTTP requests simultaneously.</p>
    <div class="search-grid">
        <label>Term <input id="q" type="text" placeholder="admin, /wp-login.php, sqlmap, ..."></label>
        <button class="btn" id="run">Search</button>
    </div>
</section>
<section class="grid two">
    <div class="card">
        <header class="card-header"><h2>Sessions</h2></header>
        <div id="results-sessions" class="results"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Alerts</h2></header>
        <div id="results-alerts" class="results"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Credentials</h2></header>
        <div id="results-credentials" class="results"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Commands</h2></header>
        <div id="results-commands" class="results"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>HTTP Requests</h2></header>
        <div id="results-http" class="results"></div>
    </div>
</section>
{% endblock %}
{% block scripts %}
<script>
document.getElementById('run').addEventListener('click', async () => {
    const term = document.getElementById('q').value.trim();
    if (!term) return;
    const base = { limit: 50 };
    const [sess, alerts, creds, cmds, http] = await Promise.all([
        fetch('/api/sessions?ip=' + encodeURIComponent(term) + '&limit=' + base.limit).then(r => r.json()),
        fetch('/api/alerts?ip=' + encodeURIComponent(term) + '&limit=' + base.limit).then(r => r.json()),
        fetch('/api/credentials?username=' + encodeURIComponent(term) + '&limit=' + base.limit).then(r => r.json()),
        fetch('/api/commands?command=' + encodeURIComponent(term) + '&limit=' + base.limit).then(r => r.json()),
        fetch('/api/http?path=' + encodeURIComponent(term) + '&limit=' + base.limit).then(r => r.json()),
    ]);
    render('results-sessions', sess, r => `${formatTime(r.started_at)} ${r.source_ip} ${r.protocol}`);
    render('results-alerts', alerts, r => `${formatTime(r.timestamp)} ${r.threat_type} ${r.severity} ${r.source_ip||''}`);
    render('results-credentials', creds, r => `${formatTime(r.timestamp)} ${r.protocol} ${r.username||''}/${r.password||''}`);
    render('results-commands', cmds, r => `${formatTime(r.timestamp)} ${r.protocol} ${r.command}`);
    render('results-http', http, r => `${formatTime(r.timestamp)} ${r.method} ${r.path} (${r.status_code})`);
});
function render(id, data, fmt) {
    const el = document.getElementById(id);
    if (!data || !data.length) { el.innerHTML = '<p class="muted">No results</p>'; return; }
    el.innerHTML = data.map(fmt).map(t => `<div class="result-row">${t}</div>`).join('');
}
function formatTime(ts){return ts?new Date(ts*1000).toLocaleString():'—';}
</script>
{% endblock %}

