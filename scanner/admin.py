from django.contrib import admin
from .models import Scan, Host, Port, Vulnerability

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "target", "scan_type", "status", "started_at")
    search_fields = ("target",)
    list_filter = ("scan_type", "status")


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "hostname", "operating_system", "status", "scan")
    search_fields = ("ip_address", "hostname")
    list_filter = ("status",)


@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ("host", "port_number", "protocol", "service", "state")
    list_filter = ("protocol", "state")
    search_fields = ("service",)


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("name", "severity", "host", "cve_id")
    list_filter = ("severity",)
    search_fields = ("name", "cve_id")