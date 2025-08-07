#!/usr/bin/env python3

import scapy.all as scapy
import netaddr
import logging
import argparse
import threading
import time
import os
import sys
from cryptography.fernet import Fernet
from datetime import datetime
from typing import Optional, Dict, Any

class EthicalPacketTool:
    def __init__(self):
        self.allowed_interfaces = ['eth0', 'wlan0', 'lo']
        self.whitelist_ips = set()
        self.blacklist_ips = set(['0.0.0.0', '255.255.255.255'])
        self.max_rate = 1000  # packets per second
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self._validate_environment()
        self._setup_logging()

    def _validate_environment(self):
        """Validate execution environment for security compliance"""
        if os.geteuid() != 0:
            raise PermissionError("This tool requires root privileges for network operations")
        
        if not self._check_scapy_permissions():
            raise RuntimeError("Insufficient Scapy permissions or configuration")
        
        # Verify network interface availability
        available_interfaces = scapy.get_if_list()
        if not any(iface in available_interfaces for iface in self.allowed_interfaces):
            raise ValueError("No authorized network interfaces available")

    def _check_scapy_permissions(self) -> bool:
        """Verify Scapy can operate correctly"""
        try:
            scapy.sniff(count=1, timeout=1)
            return True
        except PermissionError:
            return False

    def _setup_logging(self):
        """Configure comprehensive logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(f'packet_tool_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address against whitelist/blacklist"""
        try:
            netaddr.IPAddress(ip)
            if ip in self.blacklist_ips:
                self.logger.error(f"IP {ip} is blacklisted")
                return False
            if self.whitelist_ips and ip not in self.whitelist_ips:
                self.logger.error(f"IP {ip} not in whitelist")
                return False
            return True
        except netaddr.AddrFormatError:
            self.logger.error(f"Invalid IP address format: {ip}")
            return False

    def generate_packet(self, protocol: str, target_ip: str, target_port: int, 
                      payload: Optional[str] = None, **kwargs) -> Optional[scapy.Packet]:
        """Generate protocol-specific packet with custom parameters"""
        if not self._validate_ip(target_ip):
            return None

        try:
            base_packet = scapy.IP(dst=target_ip)
            
            if protocol.lower() == 'tcp':
                packet = base_packet/scapy.TCP(dport=target_port, sport=scapy.RandShort())
            elif protocol.lower() == 'udp':
                packet = base_packet/scapy.UDP(dport=target_port, sport=scapy.RandShort())
            elif protocol.lower() == 'icmp':
                packet = base_packet/scapy.ICMP()
            else:
                self.logger.error(f"Unsupported protocol: {protocol}")
                return None

            if payload:
                try:
                    encrypted_payload = self.cipher.encrypt(payload.encode())
                    packet = packet/scapy.Raw(load=encrypted_payload)
                except Exception as e:
                    self.logger.error(f"Payload encryption failed: {str(e)}")
                    return None

            # Apply additional packet modifications
            for key, value in kwargs.items():
                if hasattr(packet, key):
                    setattr(packet, key, value)
                else:
                    self.logger.warning(f"Ignoring invalid packet attribute: {key}")

            return packet
        except Exception as e:
            self.logger.error(f"Packet generation failed: {str(e)}")
            return None

    def send_packet(self, packet: scapy.Packet, count: int = 1, rate: float = 1.0, 
                   iface: Optional[str] = None) -> bool:
        """Send packet with rate limiting and interface validation"""
        if not packet:
            self.logger.error("No valid packet to send")
            return False

        if iface and iface not in self.allowed_interfaces:
            self.logger.error(f"Invalid interface: {iface}")
            return False

        if rate > self.max_rate:
            self.logger.warning(f"Rate limited to {self.max_rate} packets/second")
            rate = self.max_rate

        try:
            def transmission_thread():
                for _ in range(count):
                    scapy.send(packet, iface=iface, verbose=False)
                    time.sleep(1.0/rate)

            thread = threading.Thread(target=transmission_thread)
            thread.start()
            self.logger.info(f"Transmitting {count} packets at {rate} packets/second")
            return True
        except Exception as e:
            self.logger.error(f"Packet transmission failed: {str(e)}")
            return False

    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist"""
        if self._validate_ip(ip):
            self.whitelist_ips.add(ip)
            self.logger.info(f"Added {ip} to whitelist")

    def add_to_blacklist(self, ip: str):
        """Add IP to blacklist"""
        if self._validate_ip(ip):
            self.blacklist_ips.add(ip)
            self.logger.info(f"Added {ip} to blacklist")

def main():
    parser = argparse.ArgumentParser(description="Ethical Network Packet Generation Tool")
    parser.add_argument('--protocol', type=str, required=True, 
                       choices=['tcp', 'udp', 'icmp'], help="Protocol to use")
    parser.add_argument('--target', type=str, required=True, 
                       help="Target IP address")
    parser.add_argument('--port', type=int, default=80, 
                       help="Target port (for TCP/UDP)")
    parser.add_argument('--payload', type=str, help="Custom payload data")
    parser.add_argument('--count', type=int, default=1, 
                       help="Number of packets to send")
    parser.add_argument('--rate', type=float, default=1.0, 
                       help="Packets per second")
    parser.add_argument('--iface', type=str, help="Network interface to use")
    parser.add_argument('--whitelist', type=str, help="Add IP to whitelist")
    parser.add_argument('--blacklist', type=str, help="Add IP to blacklist")

    args = parser.parse_args()

    tool = EthicalPacketTool()

    if args.whitelist:
        tool.add_to_whitelist(args.whitelist)
        return

    if args.blacklist:
        tool.add_to_blacklist(args.blacklist)
        return

    packet = tool.generate_packet(
        protocol=args.protocol,
        target_ip=args.target,
        target_port=args.port,
        payload=args.payload
    )
    
    if packet:
        tool.send_packet(
            packet=packet,
            count=args.count,
            rate=args.rate,
            iface=args.iface
        )

def cli_interface():
    print("Ethical Network Packet Tool - Authorized Use Only")
    print("WARNING: Unauthorized network testing is illegal")
    print("Use 'python packet_tool.py --help' for command options")

if __name__ == '__main__':
    main()
