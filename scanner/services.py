import nmap


def scan_target(target):
    scanner = nmap.PortScanner()

    scanner.scan(
        hosts=target,
        arguments="-Pn -T4"
    )

    results = []

    for host in scanner.all_hosts():

        host_data = {
            "ip": host,
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state(),
            "os": "",
            "ports": []
        }

        for protocol in scanner[host].all_protocols():

            for port in sorted(scanner[host][protocol].keys()):

                service = scanner[host][protocol][port]["name"]
                state = scanner[host][protocol][port]["state"]

                host_data["ports"].append({
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "state": state
                })

        results.append(host_data)

    return results