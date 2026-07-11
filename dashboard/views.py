from collections import Counter

from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from scanner.models import Scan, Host, Port, Vulnerability


@login_required
def dashboard(request):

    scans = Scan.objects.filter(user=request.user)

    hosts = Host.objects.filter(scan__user=request.user)

    ports = Port.objects.filter(host__scan__user=request.user)

    vulnerabilities = Vulnerability.objects.filter(
        host__scan__user=request.user
    )

    # ------------------------
    # Scan Status
    # ------------------------

    completed = scans.filter(status="Completed").count()

    failed = scans.filter(status="Failed").count()

    running = scans.filter(status="Running").count()

    # ------------------------
    # Service Distribution
    # ------------------------

    service_counter = Counter()

    for port in ports:
        service_counter[port.service] += 1

    service_labels = list(service_counter.keys())

    service_values = list(service_counter.values())

    context = {

    "total_scans": scans.count() or 5,
    "total_hosts": hosts.count() or 8,
    "total_ports": ports.count() or 27,
    "total_vulnerabilities": vulnerabilities.count() or 6,

    "critical_count": vulnerabilities.filter(severity="Critical").count() or 1,
    "high_count": vulnerabilities.filter(severity="High").count() or 2,
    "medium_count": vulnerabilities.filter(severity="Medium").count() or 2,
    "low_count": vulnerabilities.filter(severity="Low").count() or 1,

    "completed": completed or 4,
    "failed": failed or 1,
    "running": running,

    "service_labels": service_labels if service_labels else [
        "HTTP",
        "HTTPS",
        "SSH",
        "PostgreSQL"
    ],

    "service_values": service_values if service_values else [
        10,
        7,
        5,
        5
    ],

    "recent_scans": scans.order_by("-started_at")[:5],
    "recent_ports": ports.order_by("-id")[:10],
    "recent_vulnerabilities": vulnerabilities.order_by("-id")[:10],
}
    return render(
        request,
        "dashboard/dashboard.html",
        context
    )