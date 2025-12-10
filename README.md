# SNMP Discovery Script

This repository contains a script for discovering network devices using SNMP (Simple Network Management Protocol). The script recursively discovers devices, their neighbors, and the interfaces they use to connect to each other. The discovered information is stored in a structured JSON format.

## Prerequisites

- Python 3.6 or higher
- `pysnmp` library
- `logging` library

## Installation

1. Clone the repository:

   ```sh
   https://github.com/KaSaNaa/SNMP-Discovery-Script.git
   cd SNMP-Discovery-Script
   ```

2. Create a virtual environment and activate it:

   ```sh
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required dependencies:

   ```sh
   pip install pysnmp
   ```

## Usage

1. Update the SNMP configuration in `snmp_manager.py`:
   - Set the SNMP version, community string, and other SNMP parameters in the `SNMPManager` class.

2. Run the script to perform recursive discovery on a single IP:

   ```sh
   python main.py
   ```

## Example

The `main.py` script performs recursive discovery on a single IP and saves the discovered devices to a JSON file.

### main.py

```python
import json
from utils.network_utils import NetworkUtils
from utils.snmp_manager import SNMPManager
from utils.graph_manager import GraphManager

# Example usage
if __name__ == "__main__":
    snmp_manager = SNMPManager(version=2, community='public')
    ip = '192.168.62.20'
    result = snmp_manager.recursive_discovery(ip)
    output_file_path = 'data/discovered_devices.json'
    with open(output_file_path, 'w') as json_file:
        json.dump(result, json_file, indent=4)
```

### snmp_manager.py

The `SNMPManager` class provides methods for SNMP discovery, retrieving neighbors, and getting local ports.

#### Methods

- `snmp_discovery(target, base_oid='1.3.6.1.2.1.1', use_next_cmd=True)`: Performs SNMP discovery using `nextCmd` or `getCmd`.
- `get_snmp_neighbors(ip)`: Retrieves SNMP neighbors using LLDP and CDP.
- `get_local_ports(target)`: Retrieves local ports using the IF-MIB OID.
- `recursive_discovery(ip, discovered_devices=None, discovered_ips=None)`: Recursively discovers devices and their neighbors.
- `get_remote_interface(neighbor_ip, source_ip, local_port_oid)`: Retrieves the remote interface name for the connection between `source_ip` and `neighbor_ip`.
- `hex_to_ip(hex_value)`: Converts a hex string to an IP address.

### Example Output

The output is a JSON file containing the discovered devices, their neighbors, and the interfaces they use to connect to each other. Here is a dummy example of what the output might look like:

```json
{
    "192.168.62.20": {
        "hostname": "MainRouter",
        "neighbors": {
            "192.168.63.1": {
                "hostname": "Neighbor1",
                "local_interface": "Et0/0",
                "remote_interface": "Gi0/1",
                "details": {
                    "hostname": "Neighbor1",
                    "neighbors": {},
                    "ports": {
                        "1": "Et0/0",
                        "2": "Et0/1"
                    }
                }
            }
        },
        "ports": {
            "1": "Et0/0",
            "2": "Et0/1",
            "3": "Et0/2",
            "4": "Et0/3",
            "5": "Vo0",
            "6": "Nu0"
        }
    }
}
```

## License

This project is licensed under the [GNU GENERAL PUBLIC LICENSE](LICENSE).

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. Open an issue or create a pull request to contribute.
