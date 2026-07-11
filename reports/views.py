from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from scanner.models import Scan, Host, Port, Vulnerability


@login_required
def report_dashboard(request):

    scans = Scan.objects.filter(user=request.user)
    hosts = Host.objects.filter(scan__user=request.user)
    ports = Port.objects.filter(host__scan__user=request.user)
    vulnerabilities = Vulnerability.objects.filter(host__scan__user=request.user)

    context = {

        "total_scans": scans.count(),

        "completed": scans.filter(status="Completed").count(),

        "running": scans.filter(status="Running").count(),

        "failed": scans.filter(status="Failed").count(),

        "total_hosts": hosts.count(),

        "total_ports": ports.count(),

        "total_vulnerabilities": vulnerabilities.count(),

        "latest_scan": scans.order_by("-started_at").first(),

        "recent_hosts": hosts.order_by("-id")[:10],

    }

    return render(
        request,
        "reports/report_dashboard.html",
        context
    )