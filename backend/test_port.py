from app.scanners.port_scanner import scan_ports

results = scan_ports("scanme.nmap.org")
for finding in results:
    print(finding)