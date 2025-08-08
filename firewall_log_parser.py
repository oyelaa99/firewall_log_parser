#!/usr/bin/env python3
"""
pfSense Firewall Log Decoder - Minimal JSON Format
A decoder for pfSense firewall syslog messages received on UDP port 514
Outputs only: src_ip, dst_ip, src_port, dst_port, timestamp, protocol, action, direction
"""

import re
import socket
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Dict, Any
import json

@dataclass
class FirewallMessage:
    """Structured representation of a firewall log message"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    action: str
    direction: str

class PfSenseFirewallDecoder:
    """pfSense firewall log decoder"""
    
    # Protocol numbers to names
    PROTOCOL_NAMES = {
        1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"
    }
    
    def __init__(self):
        self.base_pattern = re.compile(r'(?:\[([^\]]+)\]\s*)?<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(.+)')
        self.filterlog_pattern = re.compile(r'^filterlog\[\d+\]:\s+(.+)')
    
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object"""
        try:
            current_year = datetime.now().year
            timestamp_str = f"{current_year} {timestamp_str}"
            return datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.now()
    
    def parse_filterlog(self, message: str) -> Dict[str, Any]:
        """Parse pfSense firewall filter log"""
        match = self.filterlog_pattern.match(message)
        if match:
            parts = match.group(1).split(',')
            if len(parts) >= 10:
                return {
                    'action': parts[6] if parts[6] else None,
                    'direction': parts[7] if parts[7] else None,
                    'additional_data': parts[9:] if len(parts) > 9 else []
                }
        return {}
    
    def extract_network_info(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network information from firewall log"""
        network_info = {
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "action": None,
            "direction": None
        }
        
        if parsed_data:
            additional_data = parsed_data.get('additional_data', [])
            try:
                if len(additional_data) >= 13:
                    # Protocol information
                    protocol_num = additional_data[6] if additional_data[6] else None
                    protocol_name = additional_data[7] if additional_data[7] else None
                    
                    if protocol_name:
                        network_info["protocol"] = protocol_name.upper()
                    elif protocol_num:
                        try:
                            protocol_num = int(protocol_num)
                            network_info["protocol"] = self.PROTOCOL_NAMES.get(protocol_num, str(protocol_num))
                        except ValueError:
                            network_info["protocol"] = str(protocol_num)
                    
                    # IP addresses
                    network_info["src_ip"] = additional_data[9] if additional_data[9] else None
                    network_info["dst_ip"] = additional_data[10] if additional_data[10] else None
                    
                    # Ports (for TCP/UDP)
                    if len(additional_data) >= 13:
                        try:
                            src_port = additional_data[11]
                            dst_port = additional_data[12]
                            
                            if src_port and src_port.isdigit():
                                network_info["src_port"] = int(src_port)
                            if dst_port and dst_port.isdigit():
                                network_info["dst_port"] = int(dst_port)
                        except (ValueError, IndexError):
                            pass
                
                # Extract action and direction
                network_info["action"] = parsed_data.get('action')
                network_info["direction"] = parsed_data.get('direction')
                            
            except (ValueError, IndexError):
                pass
        
        return network_info
    
    def parse_message(self, raw_message: str) -> Optional[FirewallMessage]:
        """Parse a raw firewall syslog message into structured data"""
        match = self.base_pattern.match(raw_message.strip())
        if not match:
            return None
        
        timestamp_str = match.group(3)
        content = match.group(4)
        
        # Only process filterlog messages
        if 'filterlog' not in content:
            return None
        
        timestamp = self.parse_timestamp(timestamp_str)
        parsed_data = self.parse_filterlog(content)
        
        if not parsed_data:
            return None
        
        # Extract network information
        network_info = self.extract_network_info(parsed_data)
        
        return FirewallMessage(
            timestamp=timestamp,
            src_ip=network_info["src_ip"],
            dst_ip=network_info["dst_ip"],
            src_port=network_info["src_port"],
            dst_port=network_info["dst_port"],
            protocol=network_info["protocol"],
            action=network_info["action"],
            direction=network_info["direction"]
        )
    
    def format_message_json(self, msg: FirewallMessage) -> str:
        """Format parsed message as minimal JSON"""
        json_output = {
            "timestamp": msg.timestamp.isoformat(),
            "src_ip": msg.src_ip,
            "dst_ip": msg.dst_ip,
            "src_port": msg.src_port,
            "dst_port": msg.dst_port,
            "protocol": msg.protocol,
            "action": msg.action,
            "direction": msg.direction
        }
        
        return json.dumps(json_output, indent=2, default=str)

class SyslogServer:
    """UDP Syslog server for receiving pfSense firewall logs"""
    
    def __init__(self, host='0.0.0.0', port=514):
        self.host = host
        self.port = port
        self.decoder = PfSenseFirewallDecoder()
        self.running = False
        self.socket = None
    
    def start(self):
        """Start the syslog server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        print(f"Listening for firewall logs on UDP port {self.port}...")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(1024)
                message = data.decode('utf-8', errors='ignore')
                
                # Parse the message
                parsed_msg = self.decoder.parse_message(message)
                if parsed_msg:
                    print(self.decoder.format_message_json(parsed_msg))
                    
            except Exception as e:
                if self.running:
                    print(f"Error processing message: {e}")
    
    def stop(self):
        """Stop the syslog server"""
        self.running = False
        if self.socket:
            self.socket.close()

def main():
    """Main function to demonstrate the decoder"""
    # Sample firewall log for testing
    sample_log = '[192.168.1.1] <134>Jun 18 19:36:03 filterlog[8265]: 6,,,1000000105,em1,match,block,in,6,0x00,0x6cfd7,64,TCP,6,40,fe80::a00:27ff:fede:8853,2620:2d:4000:1010::117,59018,443,0,S,8772409,,64800,,mss;sackOK;TS;nop;wscale'
    
    decoder = PfSenseFirewallDecoder()
    
    print("pfSense Firewall Log Decoder - Testing")
    print("="*50)
    
    parsed = decoder.parse_message(sample_log)
    if parsed:
        print(decoder.format_message_json(parsed))
    
    print("\nStarting live syslog server...")
    
    # Start the live server
    server = SyslogServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()

if __name__ == "__main__":
    main()
