{% extends "base.html" %}
{% block title %}Live Overview &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="kpis" id="kpis">
    <div class="kpi"><span class="kpi-label">Total Sessions</span><span class="kpi-value" id="kpi-sessions">0</span></div>
    <div class="kpi"><span class="kpi-label">Active Sessions</span><span class="kpi-value" id="kpi-active">0</span></div>
    <div class="kpi"><span class="kpi-label">Alerts</span><span class="kpi-value" id="kpi-alerts">0</span></div>
    <div class="kpi"><span class="kpi-label">Credentials</span><span class="kpi-value" id="kpi-credentials">0</span></div>
    <div class="kpi"><span class="kpi-label">Commands</span><span class="kpi-value" id="kpi-commands">0</span></div>
    <div class="kpi"><span class="kpi-label">Files</span><span class="kpi-value" id="kpi-files">0</span></div>
</section>

<section class="grid two">
    <div class="card">
        <header class="card-header"><h2>Service Health</h2><span class="muted">Live</span></header>
        <table class="data-table" id="services-table">
            <thead><tr><th>Service</th><th>Protocol</th><th>Host</th><th>Port</th><th>Status</th><th>Active</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div class="card">
        <header class="card-header"><h2>Recent Alerts</h2><a href="{{ url_for('alerts_view') }}">All</a></header>
        <table class="data-table" id="alerts-table">
            <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
</section>

<section class="grid two">
    <div class="card">
        <header class="card-header"><h2>Active Sessions</h2><a href="{{ url_for('sessions_view') }}">All</a></header>
        <table class="data-table" id="active-sessions">
            <thead><tr><th>Protocol</th><th>Source IP</th><th>Port</th><th>Country</th><th>Started</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
    <div class="card">
        <header class="card-header"><h2>Top Attackers</h2><a href="{{ url_for('analytics_view') }}">Analytics</a></header>
        <table class="data-table" id="top-attackers">
            <thead><tr><th>Source IP</th><th>Country</th><th>Sessions</th><th>Severity</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>
</section>
{% endblock %}

{% block scripts %}
<script>
(function() {
    async function refresh() {
        try {
            const live = await fetch('/api/live').then(r => r.json());
            const summary = live.summary || {};
            document.getElementById('kpi-sessions').textContent = summary.total_sessions || 0;
            document.getElementById('kpi-active').textContent = summary.active_sessions || 0;
            document.getElementById('kpi-alerts').textContent = summary.total_alerts || 0;
            document.getElementById('kpi-credentials').textContent = summary.total_credentials || 0;
            document.getElementById('kpi-commands').textContent = summary.total_commands || 0;
            document.getElementById('kpi-files').textContent = summary.total_files || 0;

            const svcTbody = document.querySelector('#services-table tbody');
            svcTbody.innerHTML = '';
            (live.services || []).forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${s.name}</td><td>${s.protocol}</td><td>${s.listen_host||''}</td><td>${s.listen_port||''}</td><td><span class="badge badge-${s.status}">${s.status||''}</span></td><td>${s.active_connections||0}</td>`;
                svcTbody.appendChild(tr);
            });

            const alertsTbody = document.querySelector('#alerts-table tbody');
            alertsTbody.innerHTML = '';
            const recent = await fetch('/api/alerts?limit=10').then(r => r.json());
            (recent || []).forEach(a => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${formatTime(a.timestamp)}</td><td><span class="badge badge-${a.severity}">${a.severity}</span></td><td>${a.threat_type}</td><td>${a.source_ip||''}</td>`;
                alertsTbody.appendChild(tr);
            });

            const activeTbody = document.querySelector('#active-sessions tbody');
            activeTbody.innerHTML = '';
            (live.recent_sessions || []).slice(0, 10).forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${s.protocol}</td><td>${s.source_ip}</td><td>${s.dest_port||''}</td><td>${s.country||'—'}</td><td>${formatTime(s.started_at)}</td>`;
                activeTbody.appendChild(tr);
            });

            const analytics = await fetch('/api/analytics').then(r => r.json());
            const atkTbody = document.querySelector('#top-attackers tbody');
            atkTbody.innerHTML = '';
            (analytics.top_attackers || []).slice(0, 8).forEach(a => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${a.source_ip}</td><td>${a.country||'—'}</td><td>${a.session_count}</td><td><span class="badge badge-${a.max_severity||'informational'}">${a.max_severity||'informational'}</span></td>`;
                atkTbody.appendChild(tr);
            });
        } catch (err) {
            console.error('Refresh failed', err);
        }
    }

    function formatTime(ts) {
        if (!ts) return '—';
        const d = new Date(ts * 1000);
        return d.toLocaleString();
    }

    refresh();
    setInterval(refresh, {{ refresh_interval_ms }});
})();
</script>
{% endblock %}

