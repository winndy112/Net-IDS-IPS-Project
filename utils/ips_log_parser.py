
import re
from datetime import datetime

class IPSLogParser:
    def __init__(self):
        # Regular expression pattern for IPS log format
        self.pattern = r'Alert: (\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})\s+\[\*\*\]\s+\[([^\]]+)\]\s+"([^"]+)"\s+\[\*\*\]\s+(?:\[([^\]]+)\])?\s+\[Priority:\s+(\d+)\]\s+(?:\[([^\]]+)\])?\s+\{([^}]+)\}\s+([^->\s]*(?:\s*->\s*[^->\s]*)?)$'

    def parse_log_line(self, line):
        if not line.startswith('Alert:'):
            return None

        match = re.match(self.pattern, line.strip())
        if not match:
            return None

        timestamp, sid, message, classification, priority, app_id, protocol, ip_info = match.groups()

        # Parse IP addresses
        src_ip = dst_ip = src_port = dst_port = ''
        if '->' in ip_info:
            src, dst = ip_info.split('->')
            src = src.strip()
            dst = dst.strip()
            
            # Handle IP and port
            if ':' in src:
                src_ip, src_port = src.split(':')
            else:
                src_ip = src
                
            if ':' in dst:
                dst_ip, dst_port = dst.split(':')
            else:
                dst_ip = dst

        # Parse timestamp
        try:
            dt = datetime.strptime(timestamp, '%m/%d-%H:%M:%S.%f')
            formatted_timestamp = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        except ValueError:
            formatted_timestamp = timestamp

        return {
            'timestamp': formatted_timestamp,
            'sid': sid,
            'message': message,
            'classification': classification or 'N/A',
            'priority': priority,
            'app_id': app_id or 'N/A',
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port
        }

    def parse_log_file(self, log_content):
        alerts = []
        for line in log_content.splitlines():
            parsed = self.parse_log_line(line)
            if parsed:
                alerts.append(parsed)
        return alerts