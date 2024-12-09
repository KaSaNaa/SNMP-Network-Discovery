import json
from utils.network_utils import NetworkUtils
from utils.snmp_manager import SNMPManager
from utils.graph_manager import GraphManager

# Example usage
if __name__ == "__main__":
    output_file_path = 'data/discovered_devices.json'
    snmp_manager = SNMPManager(version=2, community='public')
    
    # Define the subnet
    subnets = ["192.168.62.0/24"]
    all_ips = NetworkUtils.get_ips_from_subnets(subnets)
    active_ips = NetworkUtils.scan_subnet(all_ips)
    
    # Initialize the dictionary to store all discovered devices
    all_discovered_devices = {}

    # Iterate over each active IP and perform recursive discovery
    for ip in active_ips:
        print(f"Starting discovery for IP: {ip}")
        discovered_devices = snmp_manager.recursive_discovery(ip)
        all_discovered_devices.update(discovered_devices)
    
    # Print the combined discovered devices in a formatted JSON string
    print(json.dumps(all_discovered_devices, indent=4))
    
    # Save the combined discovered devices to a JSON file
    with open(output_file_path, 'w') as json_file:
        json.dump(all_discovered_devices, json_file, indent=4)
        
        
    # subnet = ["192.168.62.0/24"]
    # all_ips = NetworkUtils.get_ips_from_subnets(subnet)

    # active_ips = NetworkUtils.scan_subnet(all_ips)
    # print("\n\nActive IPs")
    # for ip in active_ips:
    #     print(ip)
    
    # all_neighbors = {}
    # results = {}
    # snmp_manager = SNMPManager(2, community="public")
    
    # for ip in active_ips:
    #     result = snmp_manager.snmp_discovery(ip, base_oid="1.3.6.1.2.1.2.2.1") #.1.3.6.1.2.1.2.2.1
    #     results[ip] = result
        
    # output_file = 'snmp_discovery.json'
    # with open(output_file, 'w') as json_file:
    #     json.dump(results, json_file, indent=4)
    
    # print(f"\nSNMP data collection complete. Data saved to {output_file}")
    
    # for ip in active_ips:
    #     neighbors = snmp_manager.get_snmp_neighbors(ip)
    #     local_ports = snmp_manager.get_local_ports(ip)
    #     all_neighbors[ip] = {
    #         "neighbors": neighbors,
    #         "ports": local_ports
    #     }

    # print("\nSNMP data collection complete.")
    
    # graph_manager = GraphManager(2, community="public")
    # G = graph_manager.build_topology(active_ips)
    # graph_manager.draw_topology(G)

    # # Save the neighbors and ports data to a JSON file
    # with open('neighbors.json', 'w') as json_file:
    #     json.dump(all_neighbors, json_file, indent=4)