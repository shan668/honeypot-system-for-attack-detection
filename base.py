{% extends "base.html" %}
{% block title %}Analytics &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="grid two">
    <div class="card">
        <header class="card-header"><h2>Protocol Distribution</h2></header>
        <div id="chart-protocol" class="chart"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Severity Distribution</h2></header>
        <div id="chart-severity" class="chart"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Attack Timeline (24h)</h2></header>
        <div id="chart-timeline" class="chart"></div>
    </div>
    <div class="card">
        <header class="card-header"><h2>Session Timeline (24h)</h2></header>
        <div id="chart-sessions" class="chart"></div>
    </div>
</section>
<section class="grid two">
    <div class="card">
        <header class="card-header"><h2>Top Attacker IPs</h2></header>
        <table class="data-table" id="top-attackers">
            <thead><tr><th>Source IP</th><th>Country</th><th>City</th><th>Sessions</th><th>Severity</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div class="card">
        <header class="card-header"><h2>Top Threats</h2></header>
        <table class="data-table" id="top-threats">
            <thead><tr><th>Type</th><th>Severity</th><th>Count</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div class="card">
        <header class="card-header"><h2>Most Targeted Services</h2></header>
        <table class="data-table" id="most-targeted">
            <thead><tr><th>Protocol</th><th>Port</th><th>Sessions</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div class="card">
        <header class="card-header"><h2>Geographic Distribution</h2></header>
        <table class="data-table" id="geo-dist">
            <thead><tr><th>Country</th><th>Code</th><th>Continent</th><th>Sessions</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
</section>
<section class="grid two">
    <div class="card">
        <header class="card-header"><h2>Top Usernames</h2></header>
        <table class="data-table" id="top-users">
            <thead><tr><th>Username</th><th>Attempts</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div class="card">
        <header class="card-header"><h2>Top Passwords</h2></header>
        <table class="data-table" id="top-passwords">
            <thead><tr><th>Password</th><th>Attempts</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div class="card">
        <header class="card-header"><h2>Top URLs</h2></header>
        <table class="data-table" id="top-urls">
            <thead><tr><th>Method</th><th>Path</th><th>Count</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div class="card">
        <header class="card-header"><h2>Top Commands</h2></header>
        <table class="data-table" id="top-commands">
            <thead><tr><th>Protocol</th><th>Command</th><th>Count</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
</section>
{% endblock %}
{% block scripts %}
<script>
(async function() {
    const data = await fetch('/api/analytics').then(r => r.json());
    drawBars('chart-protocol', data.protocol_distribution.map(d => [d.protocol, d.count]));
    drawBars('chart-severity', data.severity_distribution.map(d => [d.severity, d.count]));
    drawBars('chart-timeline', (data.attack_timeline || []).map(d => [formatTime(d.bucket), d.count]));
    drawBars('chart-sessions', (data.session_timeline || []).map(d => [formatTime(d.bucket)+' '+d.protocol, d.count]));

    fillTable('top-attackers', ['source_ip','country','city','session_count','max_severity'], (data.top_attackers||[]).map(r => ({...r, max_severity: `<span class="badge badge-${r.max_severity}">${r.max_severity||'info'}</span>`})));
    fillTable('top-threats', ['threat_type','severity','count'], (data.top_threats||[]).map(r => ({...r, severity: `<span class="badge badge-${r.severity}">${r.severity}</span>`})));
    fillTable('most-targeted', ['protocol','dest_port','count'], (data.most_targeted_services||[]));
    fillTable('geo-dist', ['country','country_code','continent','count'], (data.geographic_distribution||[]));
    fillTable('top-users', ['username','count'], (data.top_usernames||[]));
    fillTable('top-passwords', ['password','count'], (data.top_passwords||[]));
    fillTable('top-urls', ['method','path','count'], (data.top_urls||[]));
    fillTable('top-commands', ['protocol','command','count'], (data.top_commands||[]));

    function fillTable(id, keys, rows) {
        const tbody = document.querySelector('#'+id+' tbody');
        tbody.innerHTML = '';
        rows.forEach(row => {
            const tr = document.createElement('tr');
            tr.innerHTML = keys.map(k => `<td>${row[k] ?? '—'}</td>`).join('');
            tbody.appendChild(tr);
        });
    }
    function drawBars(id, data) {
        const el = document.getElementById(id);
        el.innerHTML = '';
        if (!data || !data.length) { el.innerHTML = '<p class="muted">No data</p>'; return; }
        const max = Math.max(...data.map(d => d[1])) || 1;
        data.forEach(([label, value]) => {
            const row = document.createElement('div');
            row.className = 'bar-row';
            row.innerHTML = `<span class="bar-label">${label}</span><span class="bar-track"><span class="bar-fill" style="width:${(value/max*100).toFixed(1)}%"></span></span><span class="bar-value">${value}</span>`;
            el.appendChild(row);
        });
    }
    function formatTime(ts) { if (!ts) return '—'; return new Date(ts*1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}); }
    setTimeout(()=>location.reload(), 60000);
})();
</script>
{% endblock %}

