{% extends "base.html" %}
{% block title %}Alerts &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="filters">
    <label>Source IP <input type="text" id="filter-ip" placeholder="192.168.1.10"></label>
    <label>Threat Type <input type="text" id="filter-type" placeholder="brute_force"></label>
    <label>Severity
        <select id="filter-severity">
            <option value="">All</option>
            <option value="informational">Informational</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
        </select>
    </label>
    <label>Limit <input type="number" id="filter-limit" value="200" min="1" max="2000"></label>
    <button class="btn" id="apply-filters">Apply</button>
    <button class="btn" id="export-csv" type="button">Export CSV</button>
    <button class="btn" id="export-json" type="button">Export JSON</button>
</section>
<section class="card">
    <table class="data-table" id="alerts-table">
        <thead>
            <tr><th>Time</th><th>Severity</th><th>Type</th><th>Source IP</th><th>Description</th><th>Session</th></tr>
        </thead>
        <tbody></tbody>
    </table>
</section>
{% endblock %}
{% block scripts %}
<script>
(async function() {
    async function load() {
        const params = new URLSearchParams();
        const ip = document.getElementById('filter-ip').value.trim();
        const type = document.getElementById('filter-type').value.trim();
        const severity = document.getElementById('filter-severity').value;
        const limit = document.getElementById('filter-limit').value || 200;
        if (ip) params.set('ip', ip);
        if (type) params.set('threat_type', type);
        if (severity) params.set('severity', severity);
        params.set('limit', limit);
        const data = await fetch('/api/alerts?' + params.toString()).then(r => r.json());
        const tbody = document.querySelector('#alerts-table tbody');
        tbody.innerHTML = '';
        (data || []).forEach(a => {
            const tr = document.createElement('tr');
            const sessionLink = a.session_id ? `<a href="/session/${a.session_id}">${a.session_id.slice(0,8)}…</a>` : '—';
            tr.innerHTML = `<td>${formatTime(a.timestamp)}</td>
                <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
                <td>${a.threat_type}</td>
                <td>${a.source_ip||'—'}</td>
                <td>${a.description||''}</td>
                <td>${sessionLink}</td>`;
            tbody.appendChild(tr);
        });
    }
    function formatTime(ts){return ts?new Date(ts*1000).toLocaleString():'—';}
    function exportAs(fmt){
        const params = new URLSearchParams();
        const ip = document.getElementById('filter-ip').value.trim();
        const type = document.getElementById('filter-type').value.trim();
        const severity = document.getElementById('filter-severity').value;
        const limit = document.getElementById('filter-limit').value || 200;
        if (ip) params.set('ip', ip);
        if (type) params.set('threat_type', type);
        if (severity) params.set('severity', severity);
        params.set('limit', limit);
        params.set('format', fmt);
        window.location = '/api/export/alerts?' + params.toString();
    }
    document.getElementById('apply-filters').addEventListener('click', load);
    document.getElementById('export-csv').addEventListener('click', () => exportAs('csv'));
    document.getElementById('export-json').addEventListener('click', () => exportAs('json'));
    load();
    setInterval(load, {{ refresh_interval_ms }});
})();
</script>
{% endblock %}

