{% extends "base.html" %}
{% block title %}Services &middot; {{ project_name }}{% endblock %}
{% block content %}
<section class="card">
    <table class="data-table" id="services-table">
        <thead>
            <tr><th>Service</th><th>Protocol</th><th>Host</th><th>Port</th><th>Banner</th><th>Status</th><th>Active</th><th>Max Concurrency</th></tr>
        </thead>
        <tbody></tbody>
    </table>
</section>
{% endblock %}
{% block scripts %}
<script>
(async function() {
    const data = await fetch('/api/services').then(r => r.json());
    const tbody = document.querySelector('#services-table tbody');
    tbody.innerHTML = '';
    (data||[]).forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${s.name}</td><td>${s.protocol}</td><td>${s.listen_host||''}</td><td>${s.listen_port||''}</td><td><code>${s.banner||''}</code></td><td><span class="badge badge-${s.status}">${s.status||''}</span></td><td>${s.active_connections||0}</td><td>${s.max_concurrent||''}</td>`;
        tbody.appendChild(tr);
    });
})();
</script>
{% endblock %}

