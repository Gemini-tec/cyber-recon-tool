import socket
import sys
from datetime import datetime

class ReconScanner:
    """Lightweight CLI Reconnaissance Tool for Port Scanning and Banner Grabbing."""
    
    def __init__(self, target, ports=None):
        self.target = target
        # Common service ports: FTP (21), SSH (22), Telnet (23), SMTP (25), HTTP (80), HTTPS (443), Proxy (8080)
        self.ports = ports if ports else [21, 22, 23, 25, 80, 443, 8080]

    def resolve_target(self):
        """Translates domain name or hostname to IPv4 address."""
        try:
            ip = socket.gethostbyname(self.target)
            print(f"[+] Target Resolved: {self.target} -> {ip}")
            return ip
        except socket.gaierror:
            print(f"[-] Error: Could not resolve hostname '{self.target}'.")
            sys.exit(1)

    def grab_banner(self, sock, port):
        """Probes open ports to extract active service headers."""
        try:
            if port in [80, 8080]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            else:
                sock.send(b"HELP\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner.split('\n')[0] if banner else "Banner response empty"
        except Exception:
            return "No banner returned"

    def run_scan(self):
        """Executes TCP connection attempts across specified ports."""
        target_ip = self.resolve_target()
        print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)

        open_ports = 0
        for port in self.ports:
            # Create a TCP IPv4 socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)  # Prevents hanging on firewalled ports
            
            result = s.connect_ex((target_ip, port))
            if result == 0:
                open_ports += 1
                banner = self.grab_banner(s, port)
                print(f"[OPEN] Port {port:<5} | Service Banner: {banner}")
            
            s.close()

        print("=" * 50)
        print(f"[*] Scan complete. Found {open_ports} open port(s).")

if __name__ == "__main__":
    print("--- Custom Cyber Recon Tool ---")
    target_input = input("Enter target host/IP (e.g., scanme.nmap.org): ").strip()
    
    if target_input:
        scanner = ReconScanner(target_input)
        scanner.run_scan()
    else:
        print("[-] No target specified. Exiting.")
