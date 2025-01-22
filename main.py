import json
from core.network_utils import NetworkUtils
from core.snmp_manager import SNMPManager
from core.graph_manager import GraphManager

# Example usage
if __name__ == "__main__":
    # pass # Comment this line to run the code block below
    # ----------------------------------------------------------------
    # * Uncomment the following code block to perform recursive discovery on a single IP
    
    output_file_path = 'data/discovered_devices.json'
    snmp_manager = SNMPManager(version=2, community='public')
    
    ip = '192.168.62.1'
    # "1.3.6.1.2.1.2.2.1.2"    "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
    result = snmp_manager.recursive_discovery(ip)
    with open(output_file_path, 'w') as json_file:
        json.dump(result, json_file, indent=4)
    
    # ----------------------------------------------------------------