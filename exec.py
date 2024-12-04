import json
import os
import threading
import time
from utils.network_utils import NetworkUtils
from utils.snmp_manager import SNMPManager
from utils.graph_manager import GraphManager

# Function to display a rotating cursor
def show_spinner(stop_event):
    spinner = ['|', '/', '-', '\\']
    idx = 0
    while not stop_event.is_set():
        print(spinner[idx % len(spinner)], end='\r')
        idx += 1
        time.sleep(0.1)

def main():
    # Prompt user for inputs
    db_host = input("Enter DB Host IP: ")
    db_name = input("Enter DB Name: ")
    db_user = input("Enter DB User: ")
    db_password = input("Enter DB Password: ")
    if not db_password:
        db_password = ""
    snmp_version = int(input("Enter SNMP Version (1, 2, or 3): "))
    
    if snmp_version in [1, 2]:
        community = input("Enter SNMP Community: ")
        user = auth_key = priv_key = auth_protocol = priv_protocol = None
    elif snmp_version == 3:
        community = None
        user = input("Enter SNMPv3 User: ")
        auth_key = input("Enter SNMPv3 Auth Key: ")
        priv_key = input("Enter SNMPv3 Priv Key: ")
        auth_protocol = input("Enter SNMPv3 Auth Protocol (e.g., usmHMACSHAAuthProtocol): ")
        priv_protocol = input("Enter SNMPv3 Priv Protocol (e.g., usmAesCfb128Protocol): ")
    else:
        print("Invalid SNMP version. Must be 1, 2, or 3.")
        return

    subnet = input("Enter Subnet (e.g., 192.168.1.0/24): ")

    # Set environment variables
    os.environ['DB_HOST'] = db_host
    os.environ['DB_NAME'] = db_name
    os.environ['DB_USER'] = db_user
    os.environ['DB_PASSWORD'] = db_password

    all_ips = NetworkUtils.get_ips_from_subnets([subnet])

    # Start the spinner in a separate thread
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=show_spinner, args=(stop_event,))
    spinner_thread.start()

    active_ips = NetworkUtils.scan_subnet(all_ips)
    
    # Stop the spinner
    stop_event.set()
    spinner_thread.join()

    print("\n\nActive IPs")
    for ip in active_ips:
        print(ip)
    
    all_neighbors = {}
    snmp_manager = SNMPManager(snmp_version, community=community, user=user, auth_key=auth_key, priv_key=priv_key, auth_protocol=auth_protocol, priv_protocol=priv_protocol)
    
    # Start the spinner again for gathering neighbors and ports data
    stop_event.clear()
    spinner_thread = threading.Thread(target=show_spinner, args=(stop_event,))
    spinner_thread.start()

    for ip in active_ips:
        neighbors = snmp_manager.get_snmp_neighbors(ip)
        local_ports = snmp_manager.get_local_ports(ip)
        all_neighbors[ip] = {
            "neighbors": neighbors,
            "ports": local_ports
        }

    # Stop the spinner
    stop_event.set()
    spinner_thread.join()

    print("\nSNMP data collection complete.")
    
    save_path = input("Press Enter to save neighbors.json to the current working directory or enter a different path: ").strip()
    if not save_path:
        save_path = os.path.join(os.getcwd(), 'neighbors.json')
    else:
        if not os.path.isdir(os.path.dirname(save_path)):
            print("Invalid path provided. Saving to the current working directory instead.")
            save_path = os.path.join(os.getcwd(), 'neighbors.json')
    with open(save_path, 'w') as json_file:
        json.dump(all_neighbors, json_file, indent=4)
    print(f"Neighbors data saved to {save_path}")

    generate_graph = input("Do you want to generate a network topology graph? (yes/no): ").strip().lower()
    if generate_graph == 'yes':
        graph_manager = GraphManager(snmp_version, community=community, user=user, auth_key=auth_key, priv_key=priv_key, auth_protocol=auth_protocol, priv_protocol=priv_protocol)
        G = graph_manager.build_topology(active_ips)
        graph_manager.draw_topology(G)
        print("Network topology graph generated and saved as network_topology.png")

if __name__ == "__main__":
    continue_running = True
    while continue_running:
        try:
            main()
            continue_running = False
        except Exception as e:
            print(f"An error occurred: {e}")
            print("Restarting the program...\n")