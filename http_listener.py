{% extends "base.html" %}
{% block title %}Credentials &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="filters">
    <label>Username <input type="text" id="filter-username"></label>
    <label>Password <input type="text" id="filter-password"></label>
    <label>Source IP <input type="text" id="filter-ip"></label>
    <label>Limit <input type="number" id="filter-limit" value="200"></label>
    <button class="btn" id="apply-filters">Apply</button>
    <button class="btn" id="export-csv" type="button">Export CSV</button>
    <button class="btn" id="export-json" type="button">Export JSON</button>
</section>
<section class="card">
    <table class="data-table" id="creds-table">
        <thead>
            <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Protocol</th>
                <th>Username</th>
                <th>Password</th>
                <th>Risk</th>
                <th>Notes</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</section>
{% endblock %}
{% block scripts %}
<script>
(function() {
    async function load() {
        const params = new URLSearchParams();
        const u = document.getElementById('filter-username').value.trim();
        const p = document.getElementById('filter-password').value.trim();
        const ip = document.getElementById('filter-ip').value.trim();
        const l = document.getElementById('filter-limit').value || 200;
        if (u) params.set('username', u);
        if (p) params.set('password', p);
        if (ip) params.set('ip', ip);
        params.set('limit', l);
        const data = await fetch('/api/credentials?' + params.toString()).then(r => r.json());
        const tbody = document.querySelector('#creds-table tbody');
        tbody.innerHTML = '';
        (data || []).forEach(row => {
            const a = row.analysis || {};
            const tr = document.createElement('tr');
            tr.innerHTML = `<td>${formatTime(row.timestamp)}</td>
                <td><strong>${escape(row.source_ip || '—')}</strong></td>
                <td>${escape(row.protocol)}</td>
                <td>${escape(a.display_username || row.username || '')}</td>
                <td>${escape(a.display_password || row.password || '')}</td>
                <td><span class="badge badge-${escape(a.risk || 'medium')}">${escape(a.risk || 'medium')}</span></td>
                <td>${escape(a.meaning || a.intent || '')}</td>`;
            tbody.appendChild(tr);
        });
    }
    function formatTime(ts){return ts ? new Date(ts * 1000).toLocaleString() : '-';}
    function escape(s){return (s || '').toString().replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
    function exportParams(){
        const params = new URLSearchParams();
        const u = document.getElementById('filter-username').value.trim();
        const p = document.getElementById('filter-password').value.trim();
        const ip = document.getElementById('filter-ip').value.trim();
        const l = document.getElementById('filter-limit').value || 200;
        if (u) params.set('username', u);
        if (p) params.set('password', p);
        if (ip) params.set('ip', ip);
        params.set('limit', l);
        return params;
    }
    function exportAs(fmt){
        const params = exportParams();
        params.set('format', fmt);
        window.location = '/api/export/credentials?' + params.toString();
    }
    document.getElementById('apply-filters').addEventListener('click', load);
    document.getElementById('export-csv').addEventListener('click', () => exportAs('csv'));
    document.getElementById('export-json').addEventListener('click', () => exportAs('json'));
    load();
    setInterval(load, {{ refresh_interval_ms }});
})();
</script>
{% endblock %}
