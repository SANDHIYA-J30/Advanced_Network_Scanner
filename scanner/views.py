from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from django.db.models import Q

from .models import Scan, Host, Port, Vulnerability
from .services import scan_target
from .detection import detect_vulnerabilities
from .reports import generate_host_pdf

@login_required
def home(request):

    message = ""

    if request.method == "POST":

        target = request.POST.get("target")

        if target:

            scan = Scan.objects.create(
    user=request.user,
    target=target,
    scan_type="PING",
    status="Running"
)

            try:

                results = scan_target(target)

                for host in results:

                    host_obj = Host.objects.create(
                        scan=scan,
                        ip_address=host["ip"],
                        hostname=host["hostname"],
                        operating_system=host["os"],
                        status=host["state"]
                    )

                    for port in host["ports"]:

                        Port.objects.create(
                            host=host_obj,
                            port_number=port["port"],
                            protocol=port["protocol"],
                            service=port["service"],
                            state=port["state"]
                        )

                    detect_vulnerabilities(host_obj)

                scan.status = "Completed"
                scan.save()

                message = "Scan completed successfully."

            except Exception as e:

                scan.status = "Failed"
                scan.save()

                message = f"Error: {e}"

    scans = Scan.objects.filter(
    user=request.user
).order_by("-started_at")

    return render(
        request,
        "scanner/home.html",
        {
            "message": message,
            "scans": scans
        }
    )

@login_required
def host_details(request, host_id):

    host = get_object_or_404(Host, id=host_id)

    ports = Port.objects.filter(host=host).order_by("port_number")

    vulnerabilities = Vulnerability.objects.filter(host=host)

    score = 100

    for vuln in vulnerabilities:

        if vuln.severity == "Critical":
            score -= 30

        elif vuln.severity == "High":
            score -= 20

        elif vuln.severity == "Medium":
            score -= 10

        elif vuln.severity == "Low":
            score -= 5

    if score < 0:
        score = 0

    context = {
        "host": host,
        "ports": ports,
        "vulnerabilities": vulnerabilities,
        "security_score": score,
        "port_count": ports.count(),
        "vulnerability_count": vulnerabilities.count(),
    }

    return render(
        request,
        "scanner/host_details.html",
        context
    )

@login_required
def download_pdf(request, host_id):

    host = get_object_or_404(Host, id=host_id)

    ports = Port.objects.filter(host=host)

    vulnerabilities = Vulnerability.objects.filter(host=host)

    score = 100

    for vuln in vulnerabilities:

        if vuln.severity == "Critical":
            score -= 30

        elif vuln.severity == "High":
            score -= 20

        elif vuln.severity == "Medium":
            score -= 10

        elif vuln.severity == "Low":
            score -= 5

    if score < 0:
        score = 0

    pdf = generate_host_pdf(
        host,
        ports,
        vulnerabilities,
        score
    )

    response = HttpResponse(
        pdf,
        content_type="application/pdf"
    )

    response["Content-Disposition"] = (
        f'attachment; filename="Host_{host.ip_address}_Report.pdf"'
    )

    return response



@login_required
def scan_history(request):

    hosts = Host.objects.filter(
        scan__user=request.user
    ).select_related("scan").order_by("-scan__started_at")

    search = request.GET.get("search", "")

    if search:
        hosts = hosts.filter(
            ip_address__icontains=search
        )

    status = request.GET.get("status", "")

    if status:
        hosts = hosts.filter(
            scan__status=status
        )

    return render(
        request,
        "scanner/history.html",
        {
            "hosts": hosts,
            "search": search,
            "status": status,
        }
    )


@login_required
def delete_scan(request, scan_id):

    scan = get_object_or_404(
        Scan,
        id=scan_id,
        user=request.user
    )

    scan.delete()

    return redirect("/history/")