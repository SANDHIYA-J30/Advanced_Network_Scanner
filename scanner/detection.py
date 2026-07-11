from .models import Vulnerability


def detect_vulnerabilities(host):

    Vulnerability.objects.filter(host=host).delete()

    for port in host.ports.all():

        # PostgreSQL
        if port.service.lower() == "postgresql":

            Vulnerability.objects.create(
                host=host,
                name="PostgreSQL Service",
                severity="Medium",
                description="PostgreSQL database service is exposed on the network.",
                recommendation="Update PostgreSQL to the latest stable version and restrict remote access if not required."
            )

        # SMB
        elif port.service.lower() in ["microsoft-ds", "smb"]:

            Vulnerability.objects.create(
                host=host,
                name="SMB Service",
                severity="High",
                description="SMB service is accessible and could expose file sharing vulnerabilities.",
                recommendation="Disable SMBv1, enable SMB signing, and restrict SMB access using firewall rules."
            )

        # FTP
        elif port.service.lower() == "ftp":

            Vulnerability.objects.create(
                host=host,
                name="FTP Service",
                severity="High",
                description="FTP transmits data without encryption.",
                recommendation="Replace FTP with SFTP or FTPS."
            )

        # Telnet
        elif port.service.lower() == "telnet":

            Vulnerability.objects.create(
                host=host,
                name="Telnet Service",
                severity="Critical",
                description="Telnet sends credentials in plain text.",
                recommendation="Disable Telnet immediately and use SSH instead."
            )

        # HTTP
        elif port.service.lower() == "http":

            Vulnerability.objects.create(
                host=host,
                name="HTTP Service",
                severity="Low",
                description="HTTP traffic is not encrypted.",
                recommendation="Redirect all traffic to HTTPS and install a valid SSL/TLS certificate."
            )