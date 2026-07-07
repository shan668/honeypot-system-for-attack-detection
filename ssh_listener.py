{% extends "base.html" %}
{% block title %}HTTP Requests &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="filters">
    <label>Method
        <select id="filter-method">
            <option value="">All</option>
            <option>GET</option><option>POST</option><option>PUT</option>
            <option>DELETE</option><option>HEAD</option><option>OPTIONS</option><option>PATCH</option>
        </select>
    </label>
    <label>Path <input type="text" id="filter-path" placeholder="/admin"></label>
    <label>Source IP <input type="text" id="filter-ip"></label>
    <label>Limit <input type="number" id="filter-limit" value="200"></label>
    <button class="btn" id="apply-filters">Apply</button>
    <button class="btn" id="export-csv" type="button">Export CSV</button>
    <button class="btn" id="export-json" type="button">Export JSON</button>
</section>
<section class="card">
    <table class="data-table" id="http-table">
        <thead>
            <tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>User-Agent</th><th>Referrer</th><th>Source IP</th></tr>
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
        const m = document.getElementById('filter-method').value;
        const p = document.getElementById('filter-path').value.trim();
        const ip = document.getElementById('filter-ip').value.trim();
        const l = document.getElementById('filter-limit').value || 200;
        if (m) params.set('method', m);
        if (p) params.set('path', p);
        if (ip) params.set('ip', ip);
        params.set('limit', l);
        const data = await fetch('/api/http?' + params.toString()).then(r => r.json());
        const tbody = document.querySelector('#http-table tbody');
        tbody.innerHTML = '';
        (data||[]).forEach(row => {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td>${formatTime(row.timestamp)}</td><td>${row.method}</td><td><code>${row.path}</code></td><td>${row.status_code||''}</td><td>${truncate(row.user_agent,40)}</td><td>${truncate(row.referrer,40)}</td><td>${row.source_ip||''}</td>`;
            tbody.appendChild(tr);
        });
    }
    function formatTime(ts){return ts?new Date(ts*1000).toLocaleString():'—';}
    function truncate(s,n){if(!s)return '';return s.length>n?s.slice(0,n-1)+'…':s;}
    function exportAs(fmt){
        const params = new URLSearchParams();
        const m = document.getElementById('filter-method').value;
        const p = document.getElementById('filter-path').value.trim();
        const ip = document.getElementById('filter-ip').value.trim();
        const l = document.getElementById('filter-limit').value || 200;
        if (m) params.set('method', m);
        if (p) params.set('path', p);
        if (ip) params.set('ip', ip);
        params.set('limit', l);
        params.set('format', fmt);
        window.location = '/api/export/http?' + params.toString();
    }
    document.getElementById('apply-filters').addEventListener('click', load);
    document.getElementById('export-csv').addEventListener('click', () => exportAs('csv'));
    document.getElementById('export-json').addEventListener('click', () => exportAs('json'));
    load();
    setInterval(load, {{ refresh_interval_ms }});
})();
</script>
{% endblock %}

