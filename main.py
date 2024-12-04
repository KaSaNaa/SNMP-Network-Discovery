import json
from utils.network_utils import NetworkUtils
from utils.snmp_manager import SNMPManager
from utils.graph_manager import GraphManager

# Example usage
if __name__ == "__main__":
    subnet = ["192.168.62.0/24"]
    all_ips = NetworkUtils.get_ips_from_subnets(subnet)

    active_ips = NetworkUtils.scan_subnet(all_ips)
    print("\n\nActive IPs")
    for ip in active_ips:
        print(ip)
    
    all_neighbors = {}
    snmp_manager = SNMPManager(2, community="public")
    
    for ip in active_ips:
        neighbors = snmp_manager.get_snmp_neighbors(ip)
        local_ports = snmp_manager.get_local_ports(ip)
        all_neighbors[ip] = {
            "neighbors": neighbors,
            "ports": local_ports
        }

    print("\nSNMP data collection complete.")
    
    graph_manager = GraphManager(2, community="public")
    G = graph_manager.build_topology(active_ips)
    graph_manager.draw_topology(G)

    # Save the neighbors and ports data to a JSON file
    with open('neighbors.json', 'w') as json_file:
        json.dump(all_neighbors, json_file, indent=4)