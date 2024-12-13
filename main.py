import json
from core.network_utils import NetworkUtils
from core.snmp_manager import SNMPManager
from core.graph_manager import GraphManager
from core.utils import ensure_directory_exists

# Example usage
if __name__ == "__main__":
    # Comment this line to run the code block below
    snmp_manager = SNMPManager(version=2, community='public')
    
    output_file_path = 'data/discovered_devices.json'
    
    ensure_directory_exists(output_file_path)
    
    # ----------------------------------------------------------------
    # * Uncomment the following code block to perform recursive discovery on a single IP
    
    ip = '192.168.63.11'
    result = snmp_manager.recursive_discovery(ip)
    with open(output_file_path, 'w') as json_file:
          json.dump(result, json_file, indent=4)
    
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
