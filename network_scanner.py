#!/usr/bin/env python3
"""
Network Security Monitor - My First Cybersecurity Tool
This script discovers devices on your network and scans for open ports
"""

import nmap
import socket
import json
from datetime import datetime
import subprocess

class NetworkSecurityMonitor:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {}
        print("🔍 Network Security Monitor Started")
        print("=" * 50)
    
    def get_network_range(self):
        """Auto-detect your network range"""
        try:
            # Get default gateway
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    gateway = line.split()[2]
                    # Convert to network range (e.g., 192.168.1.1 -> 192.168.1.0/24)
                    network = '.'.join(gateway.split('.')[:-1]) + '.0/24'
                    return network
        except:
            # Fallback to common ranges
            return '192.168.1.0/24'
    
    def discover_devices(self):
        """Find all active devices on network"""
        network = self.get_network_range()
        print(f"🌐 Scanning network: {network}")
        
        # Ping sweep to find active hosts
        self.nm.scan(hosts=network, arguments='-sn')
        
        active_hosts = []
        for host in self.nm.all_hosts():
            host_info = {
                'ip': host,
                'hostname': self.nm[host].hostname(),
                'state': self.nm[host].state(),
                'discovered_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            active_hosts.append(host_info)
            print(f"✅ Found device: {host} ({self.nm[host].hostname() or 'Unknown'})")
        
        self.results['active_hosts'] = active_hosts
        return active_hosts
    
    def scan_ports(self, target_ip, port_range='1-1000'):
        """Scan specific host for open ports"""
        print(f"\n🔍 Port scanning {target_ip}...")
        
        try:
            self.nm.scan(target_ip, port_range)
            
            if target_ip in self.nm.all_hosts():
                open_ports = []
                
                for protocol in self.nm[target_ip].all_protocols():
                    ports = self.nm[target_ip][protocol].keys()
                    
                    for port in ports:
                        port_info = self.nm[target_ip][protocol][port]
                        if port_info['state'] == 'open':
                            service_info = {
                                'port': port,
                                'protocol': protocol,
                                'service': port_info['name'],
                                'version': port_info.get('version', ''),
                                'state': port_info['state']
                            }
                            open_ports.append(service_info)
                            print(f"  🚪 Port {port}/{protocol}: {port_info['name']} - {port_info['state']}")
                
                return open_ports
            else:
                print(f"❌ Host {target_ip} not responding")
                return []
                
        except Exception as e:
            print(f"❌ Error scanning {target_ip}: {str(e)}")
            return []
    
    def security_assessment(self, host_data):
        """Assess security risks of discovered services"""
        risk_score = 0
        vulnerabilities = []
        
        for port_info in host_data.get('open_ports', []):
            port = port_info['port']
            service = port_info['service']
            
            # Check for risky services
            high_risk_services = {
                21: 'FTP - Often configured with weak passwords',
                23: 'Telnet - Transmits passwords in plaintext',
                53: 'DNS - Can be used for DNS amplification attacks',
                135: 'RPC - Often vulnerable to buffer overflows',
                139: 'NetBIOS - Can leak system information',
                445: 'SMB - Frequent target for malware'
            }
            
            medium_risk_services = {
                22: 'SSH - Secure but can be brute-forced',
                80: 'HTTP - Web server, check for vulnerabilities',
                443: 'HTTPS - Secure web server',
                3389: 'RDP - Windows remote desktop'
            }
            
            if port in high_risk_services:
                risk_score += 3
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'risk_level': 'HIGH',
                    'description': high_risk_services[port]
                })
            elif port in medium_risk_services:
                risk_score += 1
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'risk_level': 'MEDIUM', 
                    'description': medium_risk_services[port]
                })
        
        return {
            'risk_score': risk_score,
            'vulnerabilities': vulnerabilities
        }
    
    def generate_report(self):
        """Generate a comprehensive security report"""
        report = {
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'network_summary': {
                'total_hosts_found': len(self.results.get('active_hosts', [])),
                'hosts_scanned': 0,
                'total_open_ports': 0,
                'high_risk_hosts': 0
            },
            'host_details': [],
            'security_summary': {
                'total_vulnerabilities': 0,
                'high_risk_services': 0,
                'recommendations': []
            }
        }
        
        # Analyze each host
        for host in self.results.get('active_hosts', []):
            host_detail = {
                'ip': host['ip'],
                'hostname': host['hostname'],
                'open_ports': [],
                'security_assessment': {}
            }
            
            # Skip scanning localhost to avoid issues
            if host['ip'] not in ['127.0.0.1', '::1']:
                open_ports = self.scan_ports(host['ip'], '1-100')  # Quick scan
                host_detail['open_ports'] = open_ports
                host_detail['security_assessment'] = self.security_assessment(host_detail)
                
                # Update summary stats
                report['network_summary']['total_open_ports'] += len(open_ports)
                report['security_summary']['total_vulnerabilities'] += len(host_detail['security_assessment']['vulnerabilities'])
                
                if host_detail['security_assessment']['risk_score'] >= 6:
                    report['network_summary']['high_risk_hosts'] += 1
            
            report['host_details'].append(host_detail)
            report['network_summary']['hosts_scanned'] += 1
        
        # Generate recommendations
        if report['security_summary']['total_vulnerabilities'] > 0:
            report['security_summary']['recommendations'] = [
                "Review and secure high-risk services",
                "Implement network segmentation",
                "Regular security updates and patches",
                "Monitor network traffic for anomalies",
                "Use strong authentication methods"
            ]
        else:
            report['security_summary']['recommendations'] = [
                "Good security posture detected",
                "Continue regular monitoring",
                "Keep systems updated"
            ]
        
        return report
    
    def print_summary(self, report):
        """Print a nice summary of findings"""
        print("\n" + "=" * 60)
        print("🛡️  NETWORK SECURITY SCAN RESULTS")
        print("=" * 60)
        
        print(f"📅 Scan Date: {report['scan_time']}")
        print(f"🌐 Hosts Discovered: {report['network_summary']['total_hosts_found']}")
        print(f"🔍 Hosts Scanned: {report['network_summary']['hosts_scanned']}")
        print(f"🚪 Total Open Ports: {report['network_summary']['total_open_ports']}")
        print(f"⚠️  High Risk Hosts: {report['network_summary']['high_risk_hosts']}")
        
        print(f"\n🔴 Security Issues Found: {report['security_summary']['total_vulnerabilities']}")
        
        # Show high-risk findings
        for host in report['host_details']:
            if host['security_assessment'].get('vulnerabilities'):
                print(f"\n🖥️  Host: {host['ip']} ({host['hostname'] or 'Unknown'})")
                for vuln in host['security_assessment']['vulnerabilities']:
                    if vuln['risk_level'] == 'HIGH':
                        print(f"   🔴 HIGH RISK - Port {vuln['port']}: {vuln['description']}")
                    elif vuln['risk_level'] == 'MEDIUM':
                        print(f"   🟡 MEDIUM RISK - Port {vuln['port']}: {vuln['description']}")
        
        print(f"\n💡 RECOMMENDATIONS:")
        for rec in report['security_summary']['recommendations']:
            print(f"   • {rec}")
        
        print("\n" + "=" * 60)

# Main execution
if __name__ == "__main__":
    # Create monitor instance
    monitor = NetworkSecurityMonitor()
    
    # Step 1: Discover devices
    print("Step 1: Discovering network devices...")
    active_hosts = monitor.discover_devices()
    
    if not active_hosts:
        print("❌ No active hosts found. Check your network connection.")
        exit(1)
    
    # Step 2: Generate comprehensive report
    print(f"\nStep 2: Generating security report...")
    report = monitor.generate_report()
    
    # Step 3: Display results
    monitor.print_summary(report)
    
    # Step 4: Save detailed report
    with open('network_security_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n💾 Detailed report saved to: network_security_report.json")
    print("🎉 Your scan is complete!")
