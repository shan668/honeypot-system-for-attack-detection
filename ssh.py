{% extends "base.html" %}
{% block title %}Session {{ session_id[:8] }} &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="card" id="session-meta">
    <h2>Session <code>{{ session_id }}</code></h2>
    <div id="meta-content"><p class="muted">Loading…</p></div>
</section>
<section class="grid two">
    <div class="card">
        <header class="card-header"><h2>Credentials</h2></header>
        <div id="credentials"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Commands</h2></header>
        <div id="commands"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>HTTP Requests</h2></header>
        <div id="http"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>FTP Events</h2></header>
        <div id="ftp"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>SSH Events</h2></header>
        <div id="ssh"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Files</h2></header>
        <div id="files"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Alerts</h2></header>
        <div id="alerts"></div>
    </div>
</section>
{% endblock %}
{% block scripts %}
<script>
(async function() {
    const sid = "{{ session_id }}";
    const data = await fetch('/api/session/' + sid).then(r => r.json());
    if (!data || data.error) {
        document.getElementById('meta-content').innerHTML = '<p>Session not found.</p>';
        return;
    }
    const s = data.session || {};
    document.getElementById('meta-content').innerHTML = `
        <table class="meta-table">
            <tr><th>Protocol</th><td>${s.protocol||''}</td><th>Source IP</th><td>${s.source_ip||''}</td></tr>
            <tr><th>Source Port</th><td>${s.source_port||''}</td><th>Dest Port</th><td>${s.dest_port||''}</td></tr>
            <tr><th>Hostname</th><td>${s.hostname||'—'}</td><th>MAC</th><td>${s.mac_address||'—'}</td></tr>
            <tr><th>Country</th><td>${s.country||'—'}</td><th>City</th><td>${s.city||'—'}</td></tr>
            <tr><th>ISP</th><td>${s.isp||'—'}</td><th>Continent</th><td>${s.continent||'—'}</td></tr>
            <tr><th>Started</th><td>${formatTime(s.started_at)}</td><th>Ended</th><td>${formatTime(s.ended_at)}</td></tr>
            <tr><th>Duration</th><td>${s.duration_ms||0}ms</td><th>Bytes I/O</th><td>${s.bytes_in}/${s.bytes_out}</td></tr>
            <tr><th>Outcome</th><td>${s.outcome||''}</td><th>Severity</th><td><span class="badge badge-${s.severity}">${s.severity}</span></td></tr>
        </table>`;
    renderList('credentials', data.credentials, c => `${formatTime(c.timestamp)} ${c.username||''} : ${c.password||''} ${c.success?'✔':'✗'}`);
    renderList('commands', data.commands, c => `${formatTime(c.timestamp)} [${c.protocol}] <code>${escape(c.command)}</code>`);
    renderList('http', data.http_requests, c => `${formatTime(c.timestamp)} ${c.method} ${c.path} → ${c.status_code||''} (${c.user_agent||''})`);
    renderList('ftp', data.ftp_events, c => `${formatTime(c.timestamp)} ${c.event_type} ${c.command||''} ${c.argument||''} ${c.response_code||''}`);
    renderList('ssh', data.ssh_events, c => `${formatTime(c.timestamp)} ${c.event_type} ${c.details||''}`);
    renderList('files', data.files, c => `${formatTime(c.timestamp)} ${c.action} ${c.filename||''} (${c.size||0} bytes)`);
    renderList('alerts', data.alerts, c => `${formatTime(c.timestamp)} [${c.severity}] ${c.threat_type} ${c.description||''}`);
})();
function renderList(id, items, fmt) {
    const el = document.getElementById(id);
    if (!items || !items.length) { el.innerHTML = '<p class="muted">No entries</p>'; return; }
    el.innerHTML = items.map(fmt).map(t => `<div class="result-row">${t}</div>`).join('');
}
function formatTime(ts){return ts?new Date(ts*1000).toLocaleString():'—';}
function escape(s){return (s||'').replace(/[&<>]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
</script>
{% endblock %}

