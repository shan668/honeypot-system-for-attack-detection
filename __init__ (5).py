{% extends "base.html" %}
{% block title %}Sessions &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="filters">
    <label>Source IP <input type="text" id="filter-ip" placeholder="192.168.1.10"></label>
    <label>Protocol
        <select id="filter-protocol">
            <option value="">All</option>
            <option value="ssh">SSH</option>
            <option value="ftp">FTP</option>
            <option value="http">HTTP</option>
        </select>
    </label>
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
    <label>Limit <input type="number" id="filter-limit" value="200" min="1" max="1000"></label>
    <button class="btn" id="apply-filters">Apply</button>
    <button class="btn" id="export-csv" type="button">Export CSV</button>
    <button class="btn" id="export-json" type="button">Export JSON</button>
</section>
<section class="card">
    <table class="data-table" id="sessions-table">
        <thead>
            <tr>
                <th>Started</th>
                <th>Protocol</th>
                <th>Source IP</th>
                <th>Port</th>
                <th>Country</th>
                <th>City</th>
                <th>Hostname</th>
                <th>MAC</th>
                <th>User-Agent</th>
                <th>Duration</th>
                <th>Bytes I/O</th>
                <th>Outcome</th>
                <th>Severity</th>
                <th></th>
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
        const ip = document.getElementById('filter-ip').value.trim();
        const protocol = document.getElementById('filter-protocol').value;
        const severity = document.getElementById('filter-severity').value;
        const limit = document.getElementById('filter-limit').value || 200;
        if (ip) params.set('ip', ip);
        if (protocol) params.set('protocol', protocol);
        if (severity) params.set('severity', severity);
        params.set('limit', limit);
        const data = await fetch('/api/sessions?' + params.toString()).then(r => r.json());
        const tbody = document.querySelector('#sessions-table tbody');
        tbody.innerHTML = '';
        (data || []).forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${formatTime(s.started_at)}</td>
                <td>${s.protocol}</td>
                <td>${s.source_ip}</td>
                <td>${s.dest_port||''}</td>
                <td>${s.country||'—'}</td>
                <td>${s.city||'—'}</td>
                <td>${s.hostname||'—'}</td>
                <td>${s.mac_address||'—'}</td>
                <td>${truncate(s.user_agent, 40)}</td>
                <td>${formatDuration(s.duration_ms)}</td>
                <td>${s.bytes_in}/${s.bytes_out}</td>
                <td>${s.outcome||''}</td>
                <td><span class="badge badge-${s.severity}">${s.severity}</span></td>
                <td><a class="btn btn-small" href="/session/${s.id}">Detail</a></td>`;
            tbody.appendChild(tr);
        });
    }
    function formatTime(ts) { if (!ts) return '—'; return new Date(ts*1000).toLocaleString(); }
    function formatDuration(ms) {
        if (!ms) return '0s';
        if (ms < 1000) return ms+'ms';
        const s = Math.floor(ms/1000);
        if (s < 60) return s+'s';
        const m = Math.floor(s/60);
        return m+'m '+(s%60)+'s';
    }
    function truncate(s, n) { if (!s) return ''; return s.length>n?s.slice(0,n-1)+'…':s; }
    function exportAs(fmt){
        const params = new URLSearchParams();
        const ip = document.getElementById('filter-ip').value.trim();
        const protocol = document.getElementById('filter-protocol').value;
        const severity = document.getElementById('filter-severity').value;
        const limit = document.getElementById('filter-limit').value || 200;
        if (ip) params.set('ip', ip);
        if (protocol) params.set('protocol', protocol);
        if (severity) params.set('severity', severity);
        params.set('limit', limit);
        params.set('format', fmt);
        window.location = '/api/export/sessions?' + params.toString();
    }
    document.getElementById('apply-filters').addEventListener('click', load);
    document.getElementById('export-csv').addEventListener('click', () => exportAs('csv'));
    document.getElementById('export-json').addEventListener('click', () => exportAs('json'));
    load();
    setInterval(load, {{ refresh_interval_ms }});
})();
</script>
{% endblock %}

