{% extends "base.html" %}
{% block title %}Commands &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="filters">
    <label>Command <input type="text" id="filter-command"></label>
    <label>Protocol
        <select id="filter-protocol">
            <option value="">All</option>
            <option value="ssh">SSH</option>
            <option value="ftp">FTP</option>
            <option value="http">HTTP</option>
        </select>
    </label>
    <label>Source IP <input type="text" id="filter-ip"></label>
    <label>Limit <input type="number" id="filter-limit" value="200"></label>
    <button class="btn" id="apply-filters">Apply</button>
    <button class="btn" id="export-csv" type="button">Export CSV</button>
    <button class="btn" id="export-json" type="button">Export JSON</button>
</section>
<section class="card">
    <table class="data-table" id="commands-table">
        <thead>
            <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Protocol</th>
                <th>Command</th>
                <th>Meaning</th>
                <th>Risk</th>
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
        const c = document.getElementById('filter-command').value.trim();
        const p = document.getElementById('filter-protocol').value;
        const ip = document.getElementById('filter-ip').value.trim();
        const l = document.getElementById('filter-limit').value || 200;
        if (c) params.set('command', c);
        if (p) params.set('protocol', p);
        if (ip) params.set('ip', ip);
        params.set('limit', l);
        const data = await fetch('/api/commands?' + params.toString()).then(r => r.json());
        const tbody = document.querySelector('#commands-table tbody');
        tbody.innerHTML = '';
        (data || []).forEach(row => {
            const a = row.analysis || {};
            const tr = document.createElement('tr');
            tr.innerHTML = `<td>${formatTime(row.timestamp)}</td>
                <td><strong>${escape(row.source_ip || '—')}</strong></td>
                <td>${escape(row.protocol)}</td>
                <td><code>${escape(a.display_command || row.command || '')}</code></td>
                <td>${escape(a.meaning || a.intent || '')}</td>
                <td><span class="badge badge-${escape(a.risk || 'low')}">${escape(a.risk || 'low')}</span></td>`;
            tbody.appendChild(tr);
        });
    }
    function formatTime(ts){return ts ? new Date(ts * 1000).toLocaleString() : '-';}
    function escape(s){return (s || '').toString().replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}
    function exportAs(fmt){
        const params = new URLSearchParams();
        const c = document.getElementById('filter-command').value.trim();
        const p = document.getElementById('filter-protocol').value;
        const ip = document.getElementById('filter-ip').value.trim();
        const l = document.getElementById('filter-limit').value || 200;
        if (c) params.set('command', c);
        if (p) params.set('protocol', p);
        if (ip) params.set('ip', ip);
        params.set('limit', l);
        params.set('format', fmt);
        window.location = '/api/export/commands?' + params.toString();
    }
    document.getElementById('apply-filters').addEventListener('click', load);
    document.getElementById('export-csv').addEventListener('click', () => exportAs('csv'));
    document.getElementById('export-json').addEventListener('click', () => exportAs('json'));
    load();
    setInterval(load, {{ refresh_interval_ms }});
})();
</script>
{% endblock %}
