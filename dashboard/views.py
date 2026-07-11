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

        "total_scans": scans.count(),

        "total_hosts": hosts.count(),

        "total_ports": ports.count(),

        "total_vulnerabilities": vulnerabilities.count(),

        "critical_count": vulnerabilities.filter(
            severity="Critical"
        ).count(),

        "high_count": vulnerabilities.filter(
            severity="High"
        ).count(),

        "medium_count": vulnerabilities.filter(
            severity="Medium"
        ).count(),

        "low_count": vulnerabilities.filter(
            severity="Low"
        ).count(),

        "completed": completed,
        "failed": failed,
        "running": running,

        "service_labels": service_labels,
        "service_values": service_values,

        "recent_scans": scans.order_by("-started_at")[:5],

        "recent_ports": ports.order_by("-id")[:10],

        "recent_vulnerabilities": vulnerabilities.order_by("-id")[:10],
    }

    return render(
        request,
        "dashboard/dashboard.html",
        context
    )