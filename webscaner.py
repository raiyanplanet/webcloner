import socket
import requests
import builtwith
import nmap
import ssl
import OpenSSL
import dns.resolver
from shodan import Shodan
from colorama import Fore, Style, init
import os

# Initialize colorama
init(autoreset=True)

def get_ip_address(url):
    """Get the IP address of a given URL."""
    try:
        ip_address = socket.gethostbyname(url)
        return ip_address
    except socket.error as e:
        return f"Error getting IP address: {e}"

def get_http_headers(url, user_agent=None):
    """Fetch HTTP headers from a given URL."""
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(f"http://{url}", headers=headers)
        return response.headers
    except requests.RequestException as e:
        return f"Error fetching headers: {e}"

def get_technologies(url):
    """Detect technologies used by a given URL."""
    try:
        tech = builtwith.parse(url)
        return tech
    except Exception as e:
        return f"Error detecting technologies: {e}"

def scan_ports(ip, port_range='1-1024', scan_type='tcp'):
    """Scan ports on a given IP address."""
    scanner = nmap.PortScanner()
    try:
        if scan_type == 'tcp':
            scanner.scan(ip, port_range)
        elif scan_type == 'udp':
            scanner.scan(ip, port_range, '-sU')  # Scan UDP ports
        return scanner[ip].all_protocols()
    except Exception as e:
        return f"Error scanning ports: {e}"

def get_shodan_info(api_key, ip):
    """Retrieve information from Shodan for a given IP address."""
    try:
        shodan_api = Shodan(api_key)
        info = shodan_api.host(ip)
        return {
            "Organization": info.get("org", "N/A"),
            "OS": info.get("os", "N/A"),
            "Ports": info.get("ports", []),
            "Vulnerabilities": info.get("vulns", []),
            "Device Type": info.get("device", "N/A")
        }
    except Exception as e:
        return f"Error fetching Shodan info: {e}"

def get_ssl_certificate_info(url):
    """Fetch SSL/TLS certificate information for a given URL."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((url, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                cert = ssock.getpeercert(True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                subject = dict(x509.get_subject().get_components())
                issuer = dict(x509.get_issuer().get_components())
                return {
                    "Subject": {k.decode(): v.decode() for k, v in subject.items()},
                    "Issuer": {k.decode(): v.decode() for k, v in issuer.items()},
                    "Valid From": x509.get_notBefore().decode(),
                    "Valid To": x509.get_notAfter().decode()
                }
    except Exception as e:
        return f"Error fetching SSL certificate info: {e}"

def get_dns_info(url):
    """Retrieve DNS records for a given URL."""
    try:
        dns_info = {}
        for record_type in ['A', 'MX', 'CNAME', 'TXT']:
            answers = dns.resolver.resolve(url, record_type, raise_on_no_answer=False)
            dns_info[record_type] = [rdata.to_text() for rdata in answers]
        return dns_info
    except Exception as e:
        return f"Error retrieving DNS info: {e}"

def print_section(title, content, color=Fore.GREEN):
    """Print a section of information with a title and content in color."""
    print(f"\n{color}{'='*len(title)}")
    print(f"{color}{title}")
    print(f"{color}{'='*len(title)}{Style.RESET_ALL}")
    if isinstance(content, dict):
        for key, value in content.items():
            print(f"{color}{key}: {value}{Style.RESET_ALL}")
    elif isinstance(content, list):
        for item in content:
            print(f"{color}- {item}{Style.RESET_ALL}")
    else:
        print(f"{color}{content}{Style.RESET_ALL}")

def print_http_headers(headers):
    """Print HTTP headers in a user-friendly format."""
    if isinstance(headers, dict):
        print(f"\n{Fore.YELLOW}===================")
        print(f"{Fore.YELLOW}HTTP Headers")
        print(f"{Fore.YELLOW}==================={Style.RESET_ALL}")
        for key, value in headers.items():
            print(f"{Fore.CYAN}{key}: {value}{Style.RESET_ALL}")
    else:
        print("Error or no headers to display.")

def save_to_file(filename, data):
    """Save the gathered information to a text file."""
    with open(filename, 'w') as file:
        for section, content in data.items():
            file.write(f"\n{'='*len(section)}\n")
            file.write(f"{section}\n")
            file.write(f"{'='*len(section)}\n")
            if isinstance(content, dict):
                for key, value in content.items():
                    file.write(f"{key}: {value}\n")
            elif isinstance(content, list):
                for item in content:
                    file.write(f"- {item}\n")
            else:
                file.write(f"{content}\n")
    print(f"{Fore.GREEN}Data saved to {filename}{Style.RESET_ALL}")

def main():
    print(f"{Fore.BLUE}Advanced Website Information Gathering Tool{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{'-' * 40}{Style.RESET_ALL}")

    url = input("Enter the website URL (without 'http://'): ")
    api_key = input("Enter your Shodan API Key: ")
    user_agent = input("Enter a custom User-Agent (leave blank for default): ")

    # Get and print IP address
    ip_address = get_ip_address(url)
    print_section("IP Address", ip_address, Fore.MAGENTA)

    # Get and print HTTP headers
    headers = get_http_headers(url, user_agent)
    print_http_headers(headers)

    # Get and print technologies
    technologies = get_technologies(f"http://{url}")
    print_section("Technologies", technologies, Fore.CYAN)

    # Get and print DNS info
    dns_info = get_dns_info(url)
    print_section("DNS Info", dns_info, Fore.YELLOW)

    # Get and print SSL certificate info
    ssl_certificate_info = get_ssl_certificate_info(url)
    print_section("SSL Certificate Info", ssl_certificate_info, Fore.GREEN)

    data_to_save = {
        "IP Address": ip_address,
        "HTTP Headers": headers,
        "Technologies": technologies,
        "DNS Info": dns_info,
        "SSL Certificate Info": ssl_certificate_info
    }

    if isinstance(ip_address, str) and "Error" not in ip_address:
        # Scan and print open ports (TCP)
        open_ports_tcp = scan_ports(ip_address, scan_type='tcp')
        print_section("Open TCP Ports", open_ports_tcp, Fore.RED)
        data_to_save["Open TCP Ports"] = open_ports_tcp

        # Scan and print open ports (UDP)
        open_ports_udp = scan_ports(ip_address, scan_type='udp')
        print_section("Open UDP Ports", open_ports_udp, Fore.RED)
        data_to_save["Open UDP Ports"] = open_ports_udp

        # Get and print Shodan information
        shodan_info = get_shodan_info(api_key, ip_address)
        print_section("Shodan Info", shodan_info, Fore.MAGENTA)
        data_to_save["Shodan Info"] = shodan_info
    else:
        print(f"{Fore.RED}Unable to perform port scanning and Shodan info retrieval due to IP address resolution failure.{Style.RESET_ALL}")

    # Ask user if they want to save the data to a file
    save = input(f"{Fore.YELLOW}Do you want to save this data to a text file? (Y/n): ").strip().lower()
    if save in ['y', 'yes']:
        filename = input("Enter the filename (e.g., output.txt): ")
        save_to_file(filename, data_to_save)

if __name__ == "__main__":
    main()
