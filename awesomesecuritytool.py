import nmap
import argparse
import requests
from bs4 import BeautifulSoup

def run_scan(scan_type):
    nm = nmap.PortScanner()
    
    if scan_type == "full":
        print("Running full scan...")
        nm.scan('127.0.0.1', '1-65535')  # Example target IP and port range
    elif scan_type == "quick":
        print("Running quick scan...")
        nm.scan('127.0.0.1', '1-1024')  # Example target IP and common ports
    elif scan_type == "custom":
        print("Running custom scan...")
        nm.scan('127.0.0.1', '22,80,443')  # Example custom ports
    else:
        print("Invalid scan type specified.")
        return
    
    print("Scan results:")
    for host in nm.all_hosts():
        print(f'Host: {host} ({nm[host].hostname()})')
        print(f'State: {nm[host].state()}')
        for proto in nm[host].all_protocols():
            print('----------')
            print(f'Protocol: {proto}')

            lport = nm[host][proto].keys()
            for port in sorted(lport):
                print(f'Port: {port}\tState: {nm[host][proto][port]["state"]}')

def generate_report(output_format, scan_results):
    if output_format == "html":
        with open("report.html", "w") as f:
            f.write("<html><body><h1>Scan Report</h1>")
            f.write("<p>Details...</p>")  # Include actual scan details here
            f.write("</body></html>")
        print("Report generated: report.html")
    elif output_format == "json":
        with open("report.json", "w") as f:
            f.write(str(scan_results))  # Proper JSON serialization should be done
        print("Report generated: report.json")
    elif output_format == "txt":
        with open("report.txt", "w") as f:
            f.write("Scan Report\n")
            f.write("Details...\n")  # Include actual scan details here
        print("Report generated: report.txt")
    else:
        print("Invalid output format specified.")

def main():
    parser = argparse.ArgumentParser(description="AwesomeSecurityTool - A tool for automating security scans and reporting.")
    parser.add_argument("--scan-type", choices=["full", "quick", "custom"], required=True, help="Type of scan to perform.")
    parser.add_argument("--output", choices=["html", "json", "txt"], required=True, help="Output format for the report.")
    
    args = parser.parse_args()
    
    print("Starting scan...")
    scan_results = run_scan(args.scan_type)
    generate_report(args.output, scan_results)

if __name__ == "__main__":
    main()
