from django.db import models
from django.contrib.auth.models import User


class Scan(models.Model):

    SCAN_TYPES = [
        ("PING", "Ping Scan"),
        ("TCP", "TCP Scan"),
        ("UDP", "UDP Scan"),
        ("FULL", "Full Scan"),
    ]

    STATUS_CHOICES = [
        ("Running", "Running"),
        ("Completed", "Completed"),
        ("Failed", "Failed"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="scans"
    )

    target = models.CharField(max_length=100)

    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPES,
        default="PING"
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="Running"
    )

    started_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.target}"

class Host(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='hosts')
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=100, blank=True)
    mac_address = models.CharField(max_length=50, blank=True)
    operating_system = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, default='Active')

    def __str__(self):
        return self.ip_address


class Port(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='ports')
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=10)
    service = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=20, default='Open')

    def __str__(self):
        return f"{self.host.ip_address}:{self.port_number}"


class Vulnerability(models.Model):

    SEVERITY_CHOICES = [
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
    ]

    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name="vulnerabilities"
    )

    cve_id = models.CharField(
        max_length=50,
        blank=True
    )

    name = models.CharField(
        max_length=200
    )

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES
    )

    description = models.TextField(
        blank=True
    )

    recommendation = models.TextField(
        blank=True
    )

    def __str__(self):
        return f"{self.name} ({self.severity})"