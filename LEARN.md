# Learning Guide for SNMP Discovery Script

This guide provides detailed instructions on how to use the classes and functions in the SNMP Discovery Script to discover devices on a network, retrieve information, and visualize the network topology.

## Classes and Functions

### `NetworkUtils`

The `NetworkUtils` class provides various network-related utilities.

#### Methods

- **`get_local_ip()`**: Retrieves the local IP address of the system.

  ```python
  local_ip = NetworkUtils.get_local_ip()
  print(f"Local IP: {local_ip}")
  ```

- **`save_local_ip_to_env()`**: Saves the local IP address to the `.env` file under the `DB_HOST` variable.

  ```python
  NetworkUtils.save_local_ip_to_env()
  ```

- **`get_dns_hostname(ip)`**: Retrieves the DNS hostname for a given IP address.

  ```python
  hostname = NetworkUtils.get_dns_hostname("192.168.1.1")
  print(f"Hostname: {hostname}")
  ```

- **`ping_ip(ip_str)`**: Pings an IP address to check if it is reachable.

  ```python
  reachable_ip = NetworkUtils.ping_ip("192.168.1.1")
  print(f"Reachable IP: {reachable_ip}")
  ```

- **`get_ips_from_subnets(subnets)`**: Generates a list of all possible IP addresses from a list of subnets.

  ```python
  subnets = ["192.168.1.0/24"]
  all_ips = NetworkUtils.get_ips_from_subnets(subnets)
  print(f"All IPs: {all_ips}")
  ```

- **`scan_subnet(ip_list)`**: Scans a list of IP addresses to determine which ones are active.

  ```python
  active_ips = NetworkUtils.scan_subnet(all_ips)
  print(f"Active IPs: {active_ips}")
  ```

### `SNMPManager`

The `SNMPManager` class manages SNMP-related functionalities.

#### Initialization

- **`__init__(version, community=None, user=None, auth_key=None, priv_key=None, auth_protocol=None, priv_protocol=None)`**: Initializes the SNMP manager with the specified SNMP version and credentials.

  ```python
  snmp_manager = SNMPManager(2, community="public")
  ```

#### Methods

- **`snmp_discovery(target, base_oid='1.3.6.1.2.1.1')`**: Performs SNMP discovery on a target device.

  ```python
  results = snmp_manager.snmp_discovery("192.168.1.1")
  print(f"SNMP Discovery Results: {results}")
  ```

- **`get_snmp_neighbors(ip)`**: Retrieves SNMP neighbors using LLDP and CDP protocols.

  ```python
  neighbors = snmp_manager.get_snmp_neighbors("192.168.1.1")
  print(f"SNMP Neighbors: {neighbors}")
  ```

- **`get_local_ports(target)`**: Retrieves local ports information from a network device using SNMP.

  ```python
  local_ports = snmp_manager.get_local_ports("192.168.1.1")
  print(f"Local Ports: {local_ports}")
  ```

### `DatabaseManager`

The `DatabaseManager` class handles database interactions.

#### Initialization

- **`__init__()`**: Initializes the database manager with connection details from environment variables.

  ```python
  db_manager = DatabaseManager()
  ```

#### Methods

- **`get_host_name_by_address(host_address)`**: Retrieves the hostname for a given IP address from the database.

  ```python
  hostname = db_manager.get_host_name_by_address("192.168.1.1")
  print(f"Hostname: {hostname}")
  ```

### `GraphManager`

The `GraphManager` class builds and draws network topology graphs.

#### Initialization

- **`__init__(version, community=None, user=None, auth_key=None, priv_key=None, auth_protocol=None, priv_protocol=None)`**: Initializes the graph manager with the specified SNMP version and credentials.

  ```python
  graph_manager = GraphManager(2, community="public")
  ```

#### Methods

- **`build_topology(active_ips)`**: Builds a network topology graph using SNMP data.

  ```python
  active_ips = ["192.168.1.1", "192.168.1.2"]
  G = graph_manager.build_topology(active_ips)
  ```

- **`draw_topology(graph)`**: Draws the network topology graph and saves it as an image.

  ```python
  graph_manager.draw_topology(G)
  ```

### `ScreenUtils`

The `ScreenUtils` class provides screen-related utilities.

#### Methods

- **`get_screen_size()`**: Retrieves the size of the primary monitor in pixels.

  ```python
  width, height = ScreenUtils.get_screen_size()
  print(f"Screen Size: {width}x{height}")
  ```

## Example Usage

Here is an example of how to use the script:

```python
from utils.network_utils import NetworkUtils
from utils.snmp_manager import SNMPManager
from utils.graph_manager import GraphManager
import json

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

    print("\n\nNeighbors for", ip)
    print(neighbors)
    print("Ports for", ip)
    print(local_ports)
    
    graph_manager = GraphManager(2, community="public")
    G = graph_manager.build_topology(active_ips)
    graph_manager.draw_topology(G)

    # Save the neighbors and ports data to a JSON file
    with open('neighbors.json', 'w') as json_file:
        json.dump(all_neighbors, json_file, indent=4)
```

This guide should help you understand how to use each class and function in the SNMP Discovery Script to achieve the desired results.
