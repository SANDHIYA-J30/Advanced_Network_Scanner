import socket


COMMON_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 135, 139,
    143, 443, 445,
    3306, 3389, 5432,
    5900, 6379, 8080
]


SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt"
}


def scan_target(target):

    results = []

    host = {
        "ip": target,
        "hostname": "",
        "state": "up",
        "os": "Unknown",
        "ports": []
    }

    try:
        host["hostname"] = socket.gethostbyaddr(target)[0]
    except:
        host["hostname"] = "Unknown"

    for port in COMMON_PORTS:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)

        result = s.connect_ex((target, port))

        if result == 0:

            host["ports"].append({
                "port": port,
                "protocol": "tcp",
                "service": SERVICES.get(port, "Unknown"),
                "state": "open"
            })

        s.close()

    results.append(host)

    return results