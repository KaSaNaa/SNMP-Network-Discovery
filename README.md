# SNMP Discovery Script - User Guide

## Overview
This script performs SNMP-based network device discovery, supporting SNMPv1, SNMPv2c, and SNMPv3. It identifies device types (Router/Switch/Firewall) and retrieves detailed information including interfaces, network adapters, and immediate neighbors.

## Requirements
- **Python:** 3.12 or higher
- **pysnmp:** 7.1 or higher
- **Dependencies:** Installed via `pip install -r requirements.txt`

## Installation

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Syntax
```bash
python main.py <IP_ADDRESS> [OPTIONS]
```

---

## SNMP Version Examples

### 1. SNMPv1 Discovery
```bash
python main.py 192.168.1.1 --version 1 --community public
```

**Parameters:**
- `--version 1`: Use SNMPv1 protocol
- `--community public`: SNMP community string (default: "public")

---

### 2. SNMPv2c Discovery (Default)
```bash
# Using default version (2) and community
python main.py 192.168.1.1

# Explicit parameters
python main.py 192.168.1.1 --version 2 --community private
```

**Parameters:**
- `--version 2`: Use SNMPv2c protocol (default)
- `--community private`: Custom community string

---

### 3. SNMPv3 Discovery

#### SNMPv3 with Authentication Only (authNoPriv)
```bash
python main.py 192.168.1.1 --version 3 \
  --user snmpv3user \
  --auth_key yourAuthPassword \
  --auth_proto SHA \
  --priv_proto NONE
```

#### SNMPv3 with Authentication & Privacy (authPriv) - **Recommended**
```bash
python main.py 192.168.1.1 --version 3 \
  --user snmpv3user \
  --auth_key yourAuthPassword \
  --priv_key yourPrivPassword \
  --auth_proto SHA \
  --priv_proto AES
```

**SNMPv3 Parameters:**
- `--user`: SNMPv3 username
- `--auth_key`: Authentication password
- `--priv_key`: Privacy/encryption password
- `--auth_proto`: Authentication protocol
  - `MD5` - MD5 authentication
  - `SHA` - SHA-1 authentication (recommended)
- `--priv_proto`: Privacy protocol
  - `DES` - DES encryption
  - `3DES` - Triple DES encryption
  - `AES` - AES-128 encryption (recommended)
  - `AES192` - AES-192 encryption
  - `AES256` - AES-256 encryption

---

## Command-Line Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `ip` | ✅ Yes | - | Target device IP address |
| `--version` | No | `2` | SNMP version (1, 2, or 3) |
| `--community` | For v1/v2c | `public` | SNMP community string |
| `--user` | For v3 | - | SNMPv3 username |
| `--auth_key` | For v3 | - | SNMPv3 authentication password |
| `--priv_key` | For v3 | - | SNMPv3 privacy password |
| `--auth_proto` | For v3 | - | Auth protocol (MD5/SHA) |
| `--priv_proto` | For v3 | - | Privacy protocol (DES/3DES/AES/AES192/AES256) |

---

## Output Format

### Successful Discovery
```json
{
  "Device Name": "router-01.example.com",
  "Device type": "Router",
  "IP Address": "192.168.1.1",
  "Manufacturer": "Cisco",
  "Model Number": "Unknown (Parsed from sysDescr)",
  "System OID": "1.3.6.1.4.1.9.1.1",
  "Description": "Cisco IOS Software...",
  "Serial Number": "Unknown",
  "Details": {
    "Interfaces": [
      {
        "Interface Name": "GigabitEthernet0/0",
        "Interface Number": "1",
        "MAC Address": "00:1a:2b:3c:4d:5e",
        "IP Address": "192.168.1.1"
      }
    ],
    "Network Adapters": [
      {
        "Name": "GigabitEthernet0/0",
        "IP Address": "192.168.1.1",
        "MAC Address": "00:1a:2b:3c:4d:5e",
        "Netmask": "255.255.255.0"
      }
    ],
    "Immediate Neighbors": [
      {
        "Neighbor name": "Unknown (CDP)",
        "Destination IP network": "192.168.1.2",
        "Details": "Discovered via CDP"
      }
    ]
  }
}
```

### Error Response
```json
{
  "error": "Device 192.168.1.1 is not reachable via SNMP or credentials are wrong."
}
```

---

## Device Type Specific Fields

### For Routers
```json
"Details": {
  "Interfaces": [ /* Interface details */ ],
  "Network Adapters": [ /* Adapter details */ ],
  "Immediate Neighbors": [ /* Neighbor details */ ]
}
```

### For Switches
```json
"Details": {
  "Ports": [ /* Port details with status */ ],
  "Network Adapters": [ /* Adapter details */ ],
  "Neighbors": [ /* Neighbor details */ ]
}
```

### For Firewalls
```json
"Details": {
  "Ports": [ /* Port details with status */ ],
  "Network Adapters": [ /* Adapter details */ ],
  "Neighbors": [ /* Neighbor details */ ]
}
```

---

## Discovering Multiple Devices

### Option 1: Shell Script Loop
```bash
#!/bin/bash
# discover_network.sh

IPS="192.168.1.1 192.168.1.2 192.168.1.3"
COMMUNITY="private"

for IP in $IPS; do
  echo "Discovering $IP..."
  python main.py $IP --community $COMMUNITY > output_$IP.json
done
```

### Option 2: Subnet Range Discovery
```bash
#!/bin/bash
# discover_subnet.sh

SUBNET="192.168.1"
START=1
END=254
COMMUNITY="private"

for i in $(seq $START $END); do
  IP="$SUBNET.$i"
  echo "Scanning $IP..."
  timeout 180 python main.py $IP --community $COMMUNITY > output_$IP.json 2>&1 &
  
  # Limit concurrent processes
  if (( $(jobs -r | wc -l) >= 10 )); then
    wait -n
  fi
done

wait
echo "Discovery complete!"
```

### Option 3: From IP List File
```bash
#!/bin/bash
# discover_from_file.sh

while IFS= read -r IP; do
  echo "Discovering $IP..."
  python main.py "$IP" --community private > "output_${IP//\./_}.json"
done < ip_list.txt
```

---

## Logging

All operational logs are stored in `logs/snmp_errors.log`:

```bash
# View logs in real-time
tail -f logs/snmp_errors.log

# View last 50 log entries
tail -50 logs/snmp_errors.log

# Search for errors
grep ERROR logs/snmp_errors.log
```

**Log Levels:**
- `INFO`: Normal operations (validation, OID walks, etc.)
- `ERROR`: SNMP errors, timeouts, connection failures
- `WARNING`: Max results reached, partial data

---

## Troubleshooting

### 1. "Device not reachable via SNMP"
**Causes:**
- Wrong community string
- SNMP not enabled on device
- Firewall blocking UDP port 161
- Wrong SNMP version

**Solutions:**
```bash
# Test SNMP connectivity with snmpwalk
snmpwalk -v2c -c public 192.168.1.1 system

# Check firewall rules
sudo iptables -L -n | grep 161

# Verify SNMP is running on device
# (check device documentation)
```

### 2. Script Times Out
**Cause:** Large device with many interfaces

**Solution:** Increase timeout in `core/snmp_manager.py`:
```python
timeout=120.0  # Increase from 60 to 120 seconds
```

### 3. Missing or Incorrect Data
**Cause:** SNMP MIB not fully supported by device

**Solution:** Check logs for specific OID errors:
```bash
grep "Error Indication" logs/snmp_errors.log
```

### 4. SNMPv3 Authentication Fails
**Check:**
- Username is correct
- Authentication password matches device configuration
- Privacy password matches (if using authPriv)
- Protocol types match device configuration

```bash
# Test SNMPv3 with snmpget
snmpget -v3 -l authPriv -u username -a SHA -A authpass -x AES -X privpass 192.168.1.1 sysDescr.0
```

---

## Performance Tuning

### Adjust Timeouts
Edit `core/snmp_manager.py`, line ~87:
```python
timeout=60.0  # Default timeout in seconds
```

### Adjust Max Results
Edit `core/snmp_manager.py`, line ~129:
```python
max_results = 500  # Reduce for faster scans
```

---

## Common Use Cases

### 1. Cisco Router Discovery (SNMPv2c)
```bash
python main.py 192.168.1.1 --community cisco
```

### 2. Juniper Switch Discovery (SNMPv3)
```bash
python main.py 10.0.0.1 --version 3 \
  --user admin \
  --auth_key Auth123! \
  --priv_key Priv456! \
  --auth_proto SHA \
  --priv_proto AES
```

### 3. Firewall Discovery with Custom Community
```bash
python main.py 172.16.1.1 --version 2 --community firewall_ro
```

### 4. Batch Discovery with Different Credentials
```bash
# SNMPv2c devices
python main.py 192.168.1.1 --community public > router1.json
python main.py 192.168.1.2 --community private > switch1.json

# SNMPv3 device
python main.py 192.168.1.3 --version 3 \
  --user netadmin --auth_key Pass123 --priv_key Priv456 \
  --auth_proto SHA --priv_proto AES > firewall1.json
```

---

## Security Best Practices

1. **Use SNMPv3** whenever possible for encrypted communication
2. **Use strong community strings** if using v1/v2c (not "public" or "private")
3. **Restrict SNMP access** with firewall rules to management networks only
4. **Use authPriv mode** in SNMPv3 (authentication + encryption)
5. **Store credentials securely** - don't hardcode in scripts
6. **Rotate passwords** regularly
7. **Use read-only** SNMP credentials when possible

---

## Environment Variables (Advanced)

```bash
# Set default community
export SNMP_COMMUNITY="mysecret"
python main.py 192.168.1.1  # Will use SNMP_COMMUNITY if not specified

# Set SNMPv3 credentials
export SNMP_USER="admin"
export SNMP_AUTH_KEY="authpassword"
export SNMP_PRIV_KEY="privpassword"
```

---

## Support & Contact

For issues or questions:
1. Check `logs/snmp_errors.log` for detailed error messages
2. Verify SNMP connectivity with standard SNMP tools
3. Review device-specific SNMP configuration requirements

---

## Quick Reference Card

```bash
# SNMPv1
python main.py <IP> --version 1 --community <STRING>

# SNMPv2c (default)
python main.py <IP> --community <STRING>

# SNMPv3 (auth + privacy)
python main.py <IP> --version 3 --user <USER> \
  --auth_key <AUTH> --priv_key <PRIV> \
  --auth_proto SHA --priv_proto AES

# View logs
tail -f logs/snmp_errors.log

# Batch discovery
for ip in 192.168.1.{1..10}; do
  python main.py $ip --community public > output_$ip.json
done
```
