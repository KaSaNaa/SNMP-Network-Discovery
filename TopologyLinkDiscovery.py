import json
import os
from core.network_utils import NetworkUtils
from core.snmp_manager import SNMPManager
from core.graph_manager import GraphManager
from core.utils import ensure_directory_exists
from dotenv import load_dotenv

import logging

logging.basicConfig(
    filename='app.log', level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger()

# Load environment variables
load_dotenv()

snmp_version = os.getenv('SNMP_VERSION')
snmp_community = os.getenv('SNMP_COMMUNITY')
snmp_port = os.getenv('SNMP_PORT')
auth_protocol = os.getenv('AUTH_PROTOCOL')
privacy_protocol = os.getenv('PRIVACY_PROTOCOL')
auth_password = os.getenv('AUTH_PASSWORD')
privacy_password = os.getenv('PRIVACY_PASSWORD')

# Example usage
if __name__ == "__main__":
    # Comment this line to run the code block below
    snmp_manager = SNMPManager(version=snmp_version, community=snmp_community, port=snmp_port, auth_protocol=auth_protocol, auth_password=auth_password, privacy_protocol=privacy_protocol, privacy_password=privacy_password)
    
    output_file_path = 'data/discovered_devices.json'
    
    ensure_directory_exists(output_file_path)
    
    payload = []
    
    # Set SNMP version and authentication/privacy settings based on environment variables
    if snmp_version == '3':
        snmp_manager = SNMPManager(version=3, community=snmp_community, auth_protocol=auth_protocol, auth_password=auth_password, privacy_protocol=privacy_protocol, privacy_password=privacy_password)
    else:
        snmp_manager = SNMPManager(version=2, community=snmp_community)    
    
    # ----------------------------------------------------------------
    # * Uncomment the following code block to perform recursive discovery on a single IP
    
    with open('/opt/sipmontopology/cron_data.json') as json_file:
        data = json.load(json_file)
        hostgroups = data['hostgroups']
        logger.info("Discovery on hostgroups")
        for hostgroup in hostgroups:
            hosts = hostgroup['hosts']
            devices = []
            for host in hosts:
                ip = host['address']
                result = snmp_manager.recursive_discovery(ip)
                devices.append(result)
            payload.append({
                'name': hostgroup['name'],
                'devices': devices
            })
    
    with open(output_file_path, 'w') as json_file:
          print('Writing output to file data/discoverd_devices.json')
          json.dump(payload, json_file, indent=4)
    
    # ----------------------------------------------------------------
    # * Uncomment the following code block to perform recursive discovery on a subnet
    
#     subnet = ['192.168.62.0/24']
#     ip_list = NetworkUtils.get_ips_from_subnets(subnet)
    
#     active_ips = NetworkUtils.scan_subnet(ip_list)
    
#     result = []
    
#     for ip in active_ips:
#          result.append(snmp_manager.recursive_discovery(ip))
    
#     with open(output_file_path, 'w') as json_file:
#          json.dump(result, json_file, indent=4)        
