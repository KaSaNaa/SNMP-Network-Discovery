import os
import re

def ensure_directory_exists(path):
    # Check if the path has a file extension
    if os.path.splitext(path)[1]:
        directory_path = os.path.dirname(path)
    else:
        directory_path = path
    
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

def validate_ip_address(ip_address):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    
    if ip_pattern.match(ip_address):
        parts = ip_address.split('.')
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                print(f"Invalid IP address: {ip_address}")
                return False
        return True
    else:
        print(f"Invalid IP address: {ip_address}")
        return False