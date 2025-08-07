import argparse
import logging
import os
import sys
import time
import threading
from typing import List, Optional
from scapy.all import *
from netaddr import IPNetwork, IPAddress
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(
    filename='packet_crafter.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PacketCrafter:
    """A class for crafting and sending network packets for ethical network testing."""
    
    def __init__(self, auth_key: str, whitelist: Optional[List[str]] = None, blacklist: Optional[List[str]] = None):
        """Initialize the PacketCrafter with authentication and IP restrictions.
        
        Args:
            auth_key: Key for user authentication
            whitelist: List of allowed destination IP networks
            blacklist: List of blocked destination IP networks
        """
        self.authenticated = False
        self.whitelist = [IPNetwork(ip) for ip in whitelist] if whitelist else []
        self.blacklist = [IPNetwork(ip) for ip in blacklist] if blacklist else []
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.rate_limit = 100  # Packets per second
        self.auth_key = auth_key
        self._display_legal_warning()

    def _display_legal_warning(self) -> None:
        """Display mandatory legal warning and require user consent."""
        warning = """
        WARNING: This tool is for AUTHORIZED network testing ONLY.
        Unauthorized use may violate laws and regulations.
        Ensure you have explicit permission from network owners.
        All actions will be logged for compliance.
        
        Do you agree to use this tool responsibly? (yes/no): """
        consent = input(warning).strip().lower()
        if consent != 'yes':
            logging.error("User did not provide consent. Exiting.")
            sys.exit(1)
        logging.info("User provided consent for responsible use.")

    def authenticate(self, password: str) -> bool:
        """Authenticate user before allowing packet operations.
        
        Args:
            password: User-provided password
        Returns:
            bool: True if authenticated, False otherwise
        Ethical Note: Prevents unauthorized access to sensitive network operations.
        """
        try:
            encrypted_key = self.cipher.encrypt(self.auth_key.encode())
            decrypted_key = self.cipher.decrypt(encrypted_key).decode()
            self.authenticated = (password == decrypted_key)
            if self.authenticated:
                logging.info("User authentication successful.")
            else:
                logging.error("User authentication failed.")
            return self.authenticated
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return False

    def _validate_ip(self, ip: str) -> bool:
        """Validate destination IP against whitelist and blacklist.
        
        Args:
            ip: Destination IP address
        Returns:
            bool: True if IP is allowed, False otherwise
        Ethical Note: Restricts packet destinations to authorized networks.
        """
        try:
            target_ip = IPAddress(ip)
            # Check blacklist
            for net in self.blacklist:
                if target_ip in net:
                    logging.warning(f"IP {ip} is blacklisted.")
                    return False
            # Check whitelist (if defined)
            if self.whitelist:
                for net in self.whitelist:
                    if target_ip in net:
                        return True
                logging.warning(f"IP {ip} not in whitelist.")
                return False
            return True
        except Exception as e:
            logging.error(f"IP validation error: {str(e)}")
            return False

    def _rate_limiter(self, packets_sent: int, start_time: float) -> None:
        """Enforce packet transmission rate limit.
        
        Args:
            packets_sent: Number of packets sent
            start_time: Start time of transmission
        Ethical Note: Prevents network flooding and DoS-like behavior.
        """
        elapsed = time.time() - start_time
        if elapsed > 0 and packets_sent / elapsed > self.rate_limit:
            sleep_time = (packets_sent / self.rate_limit) - elapsed
            if sleep_time > 0:
                logging.warning(f"Rate limit exceeded. Pausing for {sleep_time:.2f} seconds.")
                time.sleep(sleep_time)

    def craft_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                        payload: str, flags: str = "S") -> Packet:
        """Craft a TCP packet with specified parameters.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            payload: Packet payload
            flags: TCP flags (e.g., 'S' for SYN)
        Returns:
            Packet: Scapy TCP packet
        Ethical Note: Ensure explicit permission for spoofing and destination.
        """
        if not self._validate_ip(dst_ip):
            raise ValueError(f"Destination IP {dst_ip} is not allowed.")
        try:
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags=flags) / payload
            logging.info(f"Crafted TCP packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, flags={flags}")
            return packet
        except Exception as e:
            logging.error(f"TCP packet crafting error: {str(e)}")
            raise

    def craft_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                        payload: str) -> Packet:
        """Craft a UDP packet with specified parameters.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            payload: Packet payload
        Returns:
            Packet: Scapy UDP packet
        Ethical Note: Ensure explicit permission for spoofing and destination.
        """
        if not self._validate_ip(dst_ip):
            raise ValueError(f"Destination IP {dst_ip} is not allowed.")
        try:
            packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
            logging.info(f"Crafted UDP packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            return packet
        except Exception as e:
            logging.error(f"UDP packet crafting error: {str(e)}")
            raise

    def craft_icmp_packet(self, src_ip: str, dst_ip: str, payload: str) -> Packet:
        """Craft an ICMP packet with specified parameters.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            payload: Packet payload
        Returns:
            Packet: Scapy ICMP packet
        Ethical Note: ICMP can be used for network scanning; ensure authorized use.
        """
        if not self._validate_ip(dst_ip):
            raise ValueError(f"Destination IP {dst_ip} is not allowed.")
        try:
            packet = IP(src=src_ip, dst=dst_ip) / ICMP() / payload
            logging.info(f"Crafted ICMP packet: {src_ip} -> {dst_ip}")
            return packet
        except Exception as e:
            logging.error(f"ICMP packet crafting error: {str(e)}")
            raise

    def send_packets(self, packets: List[Packet], count: int = 1) -> None:
        """Send packets with rate limiting and logging.
        
        Args:
            packets: List of Scapy packets
            count: Number of times to send each packet
        Ethical Note: Rate limiting prevents network overload; confirm permission.
        """
        if not self.authenticated:
            logging.error("Cannot send packets: User not authenticated.")
            raise PermissionError("User authentication required.")
        
        start_time = time.time()
        packets_sent = 0
        
        def send_packet(packet: Packet) -> None:
            nonlocal packets_sent
            try:
                send(packet, verbose=False)  # Removed iface parameter to avoid warning
                packets_sent += 1
                self._rate_limiter(packets_sent, start_time)
                logging.info(f"Sent packet: {packet.summary()}")
            except Exception as e:
                logging.error(f"Packet sending error: {str(e)}")
                raise

        # Use a single thread to send packets as fast as possible within rate limit
        for _ in range(count):
            for packet in packets:
                send_packet(packet)

def main():
    """Main function to parse arguments and execute packet crafting."""
    parser = argparse.ArgumentParser(description="Ethical Network Packet Crafter")
    parser.add_argument("--src-ip", required=True, help="Source IP address")
    parser.add_argument("--dst-ip", required=True, help="Destination IP address")
    parser.add_argument("--src-port", type=int, default=12345, help="Source port")
    parser.add_argument("--dst-port", type=int, default=80, help="Destination port")
    parser.add_argument("--payload", default="TestPayload", help="Packet payload")
    parser.add_argument("--protocol", choices=["tcp", "udp", "icmp"], default="tcp", help="Protocol type")
    parser.add_argument("--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("--whitelist", nargs="*", help="Allowed IP networks")
    parser.add_argument("--blacklist", nargs="*", help="Blocked IP networks")
    
    args = parser.parse_args()

    # Initialize PacketCrafter
    crafter = PacketCrafter(auth_key="secure_key_123", whitelist=args.whitelist, blacklist=args.blacklist)
    
    # Authenticate user
    password = getpass.getpass("Enter authentication password: ")
    if not crafter.authenticate(password):
        print("Authentication failed. Exiting.")
        sys.exit(1)
    
    # Craft and send packet based on protocol
    try:
        if args.protocol == "tcp":
            packet = crafter.craft_tcp_packet(
                args.src_ip, args.dst_ip, args.src_port, args.dst_port, args.payload
            )
        elif args.protocol == "udp":
            packet = crafter.craft_udp_packet(
                args.src_ip, args.dst_ip, args.src_port, args.dst_port, args.payload
            )
        else:
            packet = crafter.craft_icmp_packet(
                args.src_ip, args.dst_ip, args.payload
            )
        
        # Confirm sensitive operation
        confirm = input(f"Confirm sending {args.count} {args.protocol.upper()} packet(s) to {args.dst_ip}? (yes/no): ")
        if confirm.lower() != 'yes':
            logging.info("User cancelled packet transmission.")
            print("Operation cancelled.")
            sys.exit(0)
        
        # Send packets
        crafter.send_packets([packet], count=args.count)
        print(f"Sent {args.count} packet(s) successfully.")
    
    except Exception as e:
        logging.error(f"Error in main execution: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
