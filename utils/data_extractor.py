import json
import os
import ipaddress

input_file_path = os.path.join(os.path.dirname(__file__), '..', 'neighbors.json')
output_file_path = os.path.join(os.path.dirname(__file__), '..', 'decoded_neighbors.json')

# Decode Hex to IP
def hex_to_ip(hex_val):
    return str(ipaddress.IPv4Address(int(hex_val, 16)))

# Decode Hex to ASCII
def hex_to_ascii(hex_str):
    return bytes.fromhex(hex_str[2:]).decode('utf-8', errors='ignore')

# Map SNMP data to CDP
def decode_snmp_neighbors(details):
    ports = details['ports']
    neighbors = details['neighbors']
    decoded_neighbors = []

    for oid, value in neighbors:
        oid_parts = oid.split('.')
        index = oid_parts[-1]  # Last part of the OID
        ip_address = device_id = interface = None

        try:
            if "1.4" in oid:  # IP Address
                ip_address = hex_to_ip(value)
            elif "1.6" in oid:  # Device ID
                device_id = hex_to_ascii(value)
            elif "1.7" in oid:  # Interface
                interface = ports.get(index, "Unknown")

            # Build neighbor entry if all parts are available
            if ip_address and device_id and interface:
                decoded_neighbors.append({
                    "ip": ip_address,
                    "device_id": device_id,
                    "interface": interface
                })
        except Exception as e:
            print(f"Error decoding neighbor {oid}: {e}")

    return decoded_neighbors

# Load the JSON data from the file
with open(input_file_path, 'r') as file:
    data = json.load(file)

decoded_data = {}

# Process each IP's neighbors and ports
for ip, details in data.items():
    neighbors = details.get('neighbors', [])
    ports = details.get('ports', {})

    if neighbors or ports:
        print(f"IP: {ip}")
        if neighbors:
            print("  Neighbors:")
            decoded_neighbors = decode_snmp_neighbors(details)
            decoded_data[ip] = {"neighbors": decoded_neighbors, "ports": ports}
            for neighbor in decoded_neighbors:
                print(f"    {neighbor}")
        if ports:
            print("  Ports:")
            for port, name in ports.items():
                print(f"    {port}: {name}")

# Save the decoded data to a new file
with open(output_file_path, 'w') as output_file:
    json.dump(decoded_data, output_file, indent=4)