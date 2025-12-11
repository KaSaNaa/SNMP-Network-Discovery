import json
import logging
import re
from core.snmp_manager import SNMPManager

# ifType values for physical network adapters (from IANA ifType definitions)
PHYSICAL_IF_TYPES = {
    '6': 'ethernetCsmacd',      # Ethernet
    '7': 'iso88023Csmacd',      # IEEE 802.3
    '9': 'iso88025TokenRing',   # Token Ring
    '15': 'fddi',               # FDDI
    '26': 'fastEther',          # Fast Ethernet (100Mbps)
    '62': 'fastEtherFX',        # Fast Ethernet FX
    '69': 'fastEther100FX',     # Fast Ethernet 100FX  
    '71': 'ieee80211',          # Wireless (WiFi)
    '117': 'gigabitEthernet',   # Gigabit Ethernet
    '169': 'tenGigabitEthernet', # 10 Gigabit Ethernet
    '209': 'bridge',            # Bridge interface (physical on some devices)
}

# ifType values for logical/virtual interfaces
LOGICAL_IF_TYPES = {
    '1': 'other',               # Other (often virtual)
    '23': 'ppp',                # PPP
    '24': 'softwareLoopback',   # Loopback
    '53': 'propVirtual',        # Proprietary Virtual
    '131': 'tunnel',            # Tunnel
    '135': 'l2vlan',            # Layer 2 VLAN
    '136': 'l3ipvlan',          # Layer 3 IP VLAN
    '150': 'mplsTunnel',        # MPLS Tunnel
    '161': 'ieee8023adLag',     # Link Aggregation (Port Channel)
}

def is_physical_interface(iface):
    """
    Determine if an interface is a physical network adapter based on ifType,
    MAC address presence, and interface name patterns.
    
    Physical adapters typically have:
    - A non-zero MAC address
    - ifType indicating physical media (6=ethernet, 71=wireless, etc.)
    - Names like eth*, en*, em*, GigabitEthernet*, FastEthernet*, etc.
    
    Logical/virtual interfaces typically have:
    - No MAC address or null MAC
    - ifType indicating virtual (24=loopback, 135=vlan, 131=tunnel)
    - Names containing 'vlan', 'loopback', 'tunnel', 'vpn', 'gre', etc.
    """
    name = iface.get("name", "").lower()
    mac = iface.get("mac", "")
    if_type = str(iface.get("if_type", "0"))
    
    # Check ifType first - most reliable
    if if_type in PHYSICAL_IF_TYPES:
        return True
    if if_type in LOGICAL_IF_TYPES:
        return False
    
    # Patterns that indicate LOGICAL/VIRTUAL interfaces
    logical_patterns = [
        r'^lo$', r'^lo\d*$',           # Loopback
        r'loopback',
        r'vlan', r'^vl\d+$', r'^svi',  # VLAN interfaces
        r'tunnel', r'^tu\d+',          # Tunnel interfaces
        r'vpn', r'^vpnt',              # VPN tunnel interfaces
        r'^gre', r'gretap',            # GRE tunnels
        r'^ipsec',                     # IPSec tunnels
        r'^null', r'^nu\d',            # Null interfaces
        r'virtual', r'miniport',       # Virtual/miniport
        r'^bridge', r'^br\d',          # Bridge interfaces (sometimes logical)
        r'^bond', r'^team',            # Bond/Team interfaces
        r'^port-channel', r'^po\d',    # Port channels (logical aggregation)
        r'^lag',                       # LAG interfaces
        r'erspan',                     # ERSPAN
    ]
    
    for pattern in logical_patterns:
        if re.search(pattern, name):
            return False
    
    # Patterns that indicate PHYSICAL interfaces
    physical_patterns = [
        r'^eth\d+$',                    # eth0, eth1 (base physical)
        r'^en[osp]\d',                  # eno1, enp0s3, ens192 (systemd naming)
        r'^em\d',                       # em1, em2 (embedded)
        r'gigabitethernet', r'^gi\d', r'^ge\d',   # Gigabit Ethernet
        r'fastethernet', r'^fa\d', r'^fe\d',      # Fast Ethernet
        r'tengigabitethernet', r'^te\d',          # 10G Ethernet
        r'hundredgige', r'^hu\d',                 # 100G Ethernet
        r'^mgmt', r'^management',                  # Management interfaces (usually physical)
        r'^serial', r'^se\d',                      # Serial interfaces
        r'^wlan', r'^wifi', r'^wl\d',             # Wireless
    ]
    
    for pattern in physical_patterns:
        if re.search(pattern, name):
            # Base physical interface (not a subinterface with dot notation)
            if '.' not in name:
                return True
    
    # Check MAC address - physical interfaces usually have valid MAC
    # A valid MAC is non-empty, not all zeros, and has proper format
    if mac and mac not in ['', '00:00:00:00:00:00', '0']:
        # Has MAC - likely physical, unless name suggests otherwise
        # Subinterfaces (eth0.100) have MAC but are logical
        if '.' in name and any(p in name for p in ['eth', 'en', 'gi', 'fa', 'te']):
            return False  # Subinterface
        return True
    
    # Default to logical if we can't determine
    return False


class DeviceDiscovery:
    def __init__(self, ip, version=2, community='public', user=None, auth_key=None, priv_key=None, auth_protocol=None, priv_protocol=None):
        self.ip = ip
        self.snmp_manager = SNMPManager(version, community, user, auth_key, priv_key, auth_protocol, priv_protocol)
        self.device_data = {}
        # Build interface index to name mapping for neighbor resolution
        self._if_index_to_name = {}

    async def discover(self):
        """
        Orchestrate the discovery process.
        """
        # 1. Validate Reachability
        if not await self.snmp_manager.validate_snmp_reachability(self.ip):
            return {"error": f"Device {self.ip} is not reachable via SNMP or credentials are wrong."}

        # 2. Basic System Info
        system_info = await self.snmp_manager.get_system_info(self.ip)
        
        # 3. Get Entity Info (Serial Number, Model) from ENTITY-MIB
        entity_info = await self.snmp_manager.get_entity_info(self.ip)
        
        # 4. Fetch Interfaces/Ports
        interfaces = await self.snmp_manager.get_full_interface_details(self.ip)
        
        # Build interface index to name mapping for neighbor resolution
        self._if_index_to_name = {iface.get("index"): iface.get("name", f"Interface_{iface.get('index')}") 
                                  for iface in interfaces}
        
        # 5. Determine Device Type using intelligent classification
        from core.utils import classify_device_type
        device_type, confidence, indicators = classify_device_type(system_info, interfaces)
        
        # 6. Extract device type description from sysDescr (keep as additional info)
        device_type_description = self._extract_device_type_from_description(system_info.get("description", ""))
        
        # 7. Fetch Neighbors (Generic)
        neighbors_raw = await self.snmp_manager.get_snmp_neighbors(self.ip)
        neighbors_formatted = self._format_neighbors(neighbors_raw)

        # 8. Determine Model - prefer ENTITY-MIB, fallback to sysDescr parsing
        model = entity_info.get("model", "Unknown")
        if model == "Unknown" or not model:
            model = self._extract_model(system_info.get("description", ""), system_info.get("object_id", ""))
        
        # 9. Get Serial Number from ENTITY-MIB
        serial_number = entity_info.get("serial_number", "Unknown")

        # 10. Separate Network Adapters (interfaces with IPs) from Ports (physical interfaces)
        # Network Adapters: Any interface that has an IP address assigned (management/L3 interfaces)
        # Ports: Only PHYSICAL interfaces (switch ports, router interfaces) - excludes VLANs, Loopbacks, etc.
        network_adapters = []
        ports = []
        
        for iface in interfaces:
            # Network Adapters are interfaces with IP addresses assigned
            # This is the device's network identity (how you manage/reach it)
            if iface.get("ips"):
                for ip_info in iface.get("ips"):
                    network_adapters.append({
                        "Name": iface.get("name"),
                        "IP Address": ip_info.get("ip"),
                        "Netmask": ip_info.get("mask"),
                        "MAC Address": iface.get("mac")
                    })
            
            # Ports: Only include PHYSICAL interfaces (matching client's expectation)
            # Excludes: VLANs, Loopbacks, Tunnels, Null interfaces, etc.
            is_physical = is_physical_interface(iface)
            
            if is_physical:
                ports.append({
                    "Interface Name": iface.get("name"),
                    "Interface Number": iface.get("index"),
                    "MAC Address": iface.get("mac"),
                    "Status": iface.get("status")
                })

        # 11. Construct Final JSON
        self.device_data = {
            "Device Name": system_info.get("name", "Unknown"),
            "Device Type": device_type,
            "Device Type Confidence": confidence,
            "Device Type Indicators": indicators,
            "Device Type Description": device_type_description,
            "IP Address": self.ip,
            "Manufacturer": self._guess_manufacturer(system_info.get("description", ""), system_info.get("object_id", "")),
            "Model Number": model,
            "System OID": system_info.get("object_id", "Unknown"),
            "Description": system_info.get("description", "Unknown"),
            "Serial Number": serial_number,
            "Details": {}
        }
        
        # Add Type specific details
        # Network Adapters: Interfaces with IP addresses (management/L3 interfaces)
        # Ports: Physical interfaces only (switch ports, router interfaces)
        self.device_data["Details"] = {
            "Network Adapters": network_adapters,
            "Ports": ports,
            "Neighbors": neighbors_formatted
        }
        
        # Apply global hex decoding to the final structure
        from core.utils import recursive_decode_hex
        self.device_data = recursive_decode_hex(self.device_data)

        return self.device_data

    def _extract_device_type_from_description(self, description):
        """
        Extracts the first two comma-separated segments from the description.
        """
        if not description:
            return "Unknown"
        
        parts = description.split(',')
        if len(parts) >= 2:
            return f"{parts[0].strip()}, {parts[1].strip()}"
        elif len(parts) == 1:
            return parts[0].strip()
        else:
            return description

    def _classify_device_deprecated(self, sys_info):
        """
        Deprecated: Classifies device using sysObjectID, sysDescr, and Capabilities.
        """
        sys_object_id = sys_info.get("object_id", "")
        description = sys_info.get("description", "").lower()
        
        # 1. Primary: sysObjectID Mapping (Placeholder/Basic patterns)
        services_val = sys_info.get("services", "0")
        
        try:
            services = int(services_val)
        except:
            services = 0
            
        # Bit 1 (value 2) = Layer 2 (Switch)
        # Bit 2 (value 4) = Layer 3 (Router)
        
        is_l2 = (services & 2)
        is_l3 = (services & 4)
        
        if "firewall" in description or "asa" in description or "fortigate" in description or "palo alto" in description:
            return "Firewall"
        elif is_l3 and not is_l2:
            return "Router"
        elif is_l2 and not is_l3:
            return "Switch"
        elif is_l3 and is_l2:
            # L3 Switch or Router with L2
            if "switch" in description or "catalyst" in description:
                return "Switch"
            return "Router"
        else:
            return "Unknown"

    def _guess_manufacturer(self, description, object_id=None):
        """
        Guess the manufacturer from description and/or sysObjectID.
        """
        # First try to detect from OID (more reliable)
        if object_id:
            # Cisco: 1.3.6.1.4.1.9
            if object_id.startswith("1.3.6.1.4.1.9."):
                return "Cisco"
            # Juniper: 1.3.6.1.4.1.2636
            elif "1.3.6.1.4.1.2636" in object_id:
                return "Juniper"
            # Fortinet: 1.3.6.1.4.1.12356
            elif "1.3.6.1.4.1.12356" in object_id:
                return "Fortinet"
            # Palo Alto: 1.3.6.1.4.1.25461
            elif "1.3.6.1.4.1.25461" in object_id:
                return "Palo Alto"
            # HP/Aruba: 1.3.6.1.4.1.11 (HP) or 1.3.6.1.4.1.14823 (Aruba)
            elif "1.3.6.1.4.1.11." in object_id or "1.3.6.1.4.1.14823" in object_id:
                return "HP/Aruba"
            # Dell: 1.3.6.1.4.1.674
            elif "1.3.6.1.4.1.674" in object_id:
                return "Dell"
            # Huawei: 1.3.6.1.4.1.2011
            elif "1.3.6.1.4.1.2011" in object_id:
                return "Huawei"
            # Net-SNMP (Linux): 1.3.6.1.4.1.8072
            elif "1.3.6.1.4.1.8072" in object_id:
                return "Linux (Net-SNMP)"
            # CheckPoint: 1.3.6.1.4.1.2620
            elif "1.3.6.1.4.1.2620" in object_id:
                return "CheckPoint"
            # Ubiquiti: 1.3.6.1.4.1.41112
            elif "1.3.6.1.4.1.41112" in object_id:
                return "Ubiquiti"
            # MikroTik: 1.3.6.1.4.1.14988
            elif "1.3.6.1.4.1.14988" in object_id:
                return "MikroTik"
            # Arista: 1.3.6.1.4.1.30065
            elif "1.3.6.1.4.1.30065" in object_id:
                return "Arista"
        
        # Fallback to description-based detection
        description = description.lower() if description else ""
        if "cisco" in description:
            return "Cisco"
        elif "juniper" in description:
            return "Juniper"
        elif "huawei" in description:
            return "Huawei"
        elif "arista" in description:
            return "Arista"
        elif "hp" in description or "hpe" in description or "aruba" in description:
            return "HP/Aruba"
        elif "fortinet" in description or "fortigate" in description:
            return "Fortinet"
        elif "palo alto" in description or "panorama" in description:
            return "Palo Alto"
        elif "checkpoint" in description:
            return "CheckPoint"
        elif "dell" in description or "powerconnect" in description:
            return "Dell"
        elif "netgear" in description:
            return "Netgear"
        elif "ubiquiti" in description or "unifi" in description:
            return "Ubiquiti"
        elif "mikrotik" in description:
            return "MikroTik"
        elif "linux" in description:
            return "Linux"
        elif "windows" in description:
            return "Windows"
        else:
            return "Unknown"

    def _extract_model(self, description, object_id=None):
        """
        Extract model information from sysDescr and/or sysObjectID.
        Uses known OID-to-model mappings and description parsing.
        """
        # Known sysObjectID to model mappings for Cisco devices
        cisco_oid_models = {
            "1.3.6.1.4.1.9.1.516": "Catalyst 3750",
            "1.3.6.1.4.1.9.1.696": "Catalyst 3750-E",
            "1.3.6.1.4.1.9.1.1208": "Catalyst 2960",
            "1.3.6.1.4.1.9.1.695": "Catalyst 2960",
            "1.3.6.1.4.1.9.1.950": "Catalyst 2960-S",
            "1.3.6.1.4.1.9.1.1016": "Catalyst 3560",
            "1.3.6.1.4.1.9.1.559": "Catalyst 3550",
            "1.3.6.1.4.1.9.1.366": "Catalyst 2950",
            "1.3.6.1.4.1.9.1.1745": "Catalyst 3850",
            "1.3.6.1.4.1.9.1.2494": "Catalyst 9200",
            "1.3.6.1.4.1.9.1.2495": "Catalyst 9300",
            "1.3.6.1.4.1.9.1.1227": "Nexus",
            "1.3.6.1.4.1.9.1.122": "2600 Series Router",
            "1.3.6.1.4.1.9.1.208": "3600 Series Router",
            "1.3.6.1.4.1.9.1.283": "7200 Series Router",
            "1.3.6.1.4.1.9.1.620": "ISR Router",
            "1.3.6.1.4.1.9.1.1045": "CSR 1000V",
            "1.3.6.1.4.1.9.1.896": "ISR G2 Router",
            "1.3.6.1.4.1.9.1.417": "ASA 5500",
            "1.3.6.1.4.1.9.1.745": "ASA 5500",
            "1.3.6.1.4.1.9.1.670": "FWSM",
            "1.3.6.1.4.1.9.1.669": "PIX Firewall",
            "1.3.6.1.4.1.9.1.2228": "Firepower",
            "1.3.6.1.4.1.9.1.1": "IOS Device",
        }
        
        # Check OID mapping first
        if object_id:
            for oid, model in cisco_oid_models.items():
                if object_id.startswith(oid):
                    return model
        
        # Try to extract from description
        if description:
            desc_lower = description.lower()
            
            # Cisco software name patterns
            # Example: "C3750E-UNIVERSALK9-M" -> Catalyst 3750-E
            # Example: "C2960S-UNIVERSALK9-M" -> Catalyst 2960-S
            import re
            
            # Look for Catalyst model patterns
            catalyst_match = re.search(r'(catalyst\s*[\d]+[a-z]*)', desc_lower)
            if catalyst_match:
                return catalyst_match.group(1).title()
            
            # Look for C#### patterns (Cisco shorthand)
            c_match = re.search(r'\b(c\d{4}[a-z]*)\b', desc_lower)
            if c_match:
                model_code = c_match.group(1).upper()
                # Map common codes
                if model_code.startswith('C37'):
                    return f"Catalyst {model_code[1:]}"
                elif model_code.startswith('C29'):
                    return f"Catalyst {model_code[1:]}"
                elif model_code.startswith('C35'):
                    return f"Catalyst {model_code[1:]}"
                elif model_code.startswith('C38'):
                    return f"Catalyst {model_code[1:]}"
                elif model_code.startswith('C92') or model_code.startswith('C93'):
                    return f"Catalyst {model_code[1:]}"
                return f"Cisco {model_code}"
            
            # Look for ASA patterns
            if "asa" in desc_lower:
                asa_match = re.search(r'asa\s*(\d+)', desc_lower)
                if asa_match:
                    return f"ASA {asa_match.group(1)}"
                return "ASA"
            
            # Look for Nexus patterns
            if "nexus" in desc_lower or "nx-os" in desc_lower:
                nexus_match = re.search(r'nexus\s*(\d+)', desc_lower)
                if nexus_match:
                    return f"Nexus {nexus_match.group(1)}"
                return "Nexus"
            
            # Look for ISR patterns
            if "isr" in desc_lower:
                isr_match = re.search(r'isr\s*(\d+)', desc_lower)
                if isr_match:
                    return f"ISR {isr_match.group(1)}"
                return "ISR Router"
            
            # FortiGate patterns
            if "fortigate" in desc_lower:
                fg_match = re.search(r'fortigate[- ]*(\S+)', desc_lower)
                if fg_match:
                    return f"FortiGate {fg_match.group(1)}"
                return "FortiGate"
            
            # Palo Alto patterns
            if "palo alto" in desc_lower or "pan-os" in desc_lower:
                return "Palo Alto"
                
        return "Unknown"

    def _format_neighbors(self, neighbors_raw):
        """
        Format raw neighbor data from LLDP/CDP into structured neighbor information.
        Properly parses LLDP and CDP OIDs to extract meaningful neighbor data.
        """
        formatted = []
        neighbor_data = {}  # Track neighbors by interface index
        
        # LLDP OID structure: 1.0.8802.1.1.2.1.4.1.1.X.timeFilter.localIfIndex.remoteIndex
        # Where X is the column:
        # 4 = lldpRemChassisIdSubtype
        # 5 = lldpRemChassisId
        # 6 = lldpRemPortIdSubtype  
        # 7 = lldpRemPortId
        # 8 = lldpRemPortDesc
        # 9 = lldpRemSysName
        # 10 = lldpRemSysDesc
        
        # CDP OID structure: 1.3.6.1.4.1.9.9.23.1.2.1.1.X.ifIndex.deviceIndex
        # Where X is the column:
        # 4 = cdpCacheAddress (IP in hex)
        # 5 = cdpCacheVersion
        # 6 = cdpCacheDeviceId
        # 7 = cdpCacheDevicePort
        # 8 = cdpCachePlatform
        
        for oid, value in neighbors_raw:
            # Parse LLDP data
            if "1.0.8802.1.1.2.1.4" in oid:
                # Extract the column type and indices from OID
                oid_parts = oid.split(".")
                try:
                    # Find the position of "1" after "4" in the OID path (1.0.8802.1.1.2.1.4.1.1.X...)
                    if "1.0.8802.1.1.2.1.4.1.1" in oid:
                        # Get the part after 1.0.8802.1.1.2.1.4.1.1
                        suffix = oid.split("1.0.8802.1.1.2.1.4.1.1.")[1] if "1.0.8802.1.1.2.1.4.1.1." in oid else ""
                        parts = suffix.split(".")
                        if len(parts) >= 3:
                            column_type = parts[0]
                            local_if_index = parts[2] if len(parts) > 2 else "unknown"
                            
                            key = f"lldp_{local_if_index}"
                            if key not in neighbor_data:
                                neighbor_data[key] = {
                                    "protocol": "LLDP",
                                    "local_interface": local_if_index
                                }
                            
                            # Map column types to fields
                            if column_type == "5":  # Chassis ID (often MAC)
                                neighbor_data[key]["chassis_id"] = self._format_lldp_value(value)
                            elif column_type == "7":  # Port ID
                                neighbor_data[key]["remote_port"] = self._format_lldp_value(value)
                            elif column_type == "8":  # Port Description
                                neighbor_data[key]["remote_port_desc"] = self._format_lldp_value(value)
                            elif column_type == "9":  # System Name
                                neighbor_data[key]["neighbor_name"] = self._format_lldp_value(value)
                            elif column_type == "10":  # System Description
                                neighbor_data[key]["system_desc"] = self._format_lldp_value(value)
                except (IndexError, ValueError):
                    pass
            
            # Parse CDP data
            elif "9.9.23.1.2.1.1" in oid or "1.3.6.1.4.1.9.9.23.1.2.1.1" in oid:
                oid_parts = oid.split(".")
                try:
                    # CDP OID format: ...23.1.2.1.1.X.ifIndex.deviceIndex
                    # Find the column number
                    if ".1.3.6.1.4.1.9.9.23.1.2.1.1." in oid:
                        suffix = oid.split(".1.3.6.1.4.1.9.9.23.1.2.1.1.")[1]
                    else:
                        suffix = oid.split("9.9.23.1.2.1.1.")[1] if "9.9.23.1.2.1.1." in oid else ""
                    
                    parts = suffix.split(".")
                    if len(parts) >= 2:
                        column_type = parts[0]
                        local_if_index = parts[1]
                        
                        key = f"cdp_{local_if_index}"
                        if key not in neighbor_data:
                            neighbor_data[key] = {
                                "protocol": "CDP",
                                "local_interface": local_if_index
                            }
                        
                        if column_type == "4":  # Address (IP in hex)
                            neighbor_data[key]["neighbor_ip"] = self._hex_to_ip(value)
                        elif column_type == "5":  # Version
                            neighbor_data[key]["version"] = self._format_lldp_value(value)
                        elif column_type == "6":  # Device ID (hostname)
                            neighbor_data[key]["neighbor_name"] = self._format_lldp_value(value)
                        elif column_type == "7":  # Remote Port
                            neighbor_data[key]["remote_port"] = self._format_lldp_value(value)
                        elif column_type == "8":  # Platform
                            neighbor_data[key]["platform"] = self._format_lldp_value(value)
                except (IndexError, ValueError):
                    pass
        
        # Log what we found for debugging
        cdp_count = sum(1 for k in neighbor_data.keys() if k.startswith('cdp_'))
        lldp_count = sum(1 for k in neighbor_data.keys() if k.startswith('lldp_'))
        logging.info(f"Neighbor discovery: Found {cdp_count} CDP entries, {lldp_count} LLDP entries")
        
        # Merge CDP and LLDP data for the same interface
        # Build a mapping by local interface index
        merged_by_interface = {}
        
        for key, data in neighbor_data.items():
            local_if_index = data.get("local_interface", "Unknown")
            protocol = data.get("protocol", "Unknown")
            
            if local_if_index not in merged_by_interface:
                merged_by_interface[local_if_index] = {"cdp": None, "lldp": None}
            
            if protocol == "CDP":
                merged_by_interface[local_if_index]["cdp"] = data
            elif protocol == "LLDP":
                merged_by_interface[local_if_index]["lldp"] = data
        
        # Convert merged data to formatted list
        # Prefer CDP over LLDP when both exist for the same interface
        for local_if_index, protocols in merged_by_interface.items():
            cdp_data = protocols.get("cdp")
            lldp_data = protocols.get("lldp")
            
            # Prefer CDP if available, otherwise use LLDP
            if cdp_data:
                data = cdp_data
                # If LLDP has additional info that CDP doesn't, merge it
                if lldp_data:
                    if not data.get("neighbor_name") and lldp_data.get("neighbor_name"):
                        data["neighbor_name"] = lldp_data["neighbor_name"]
                    if not data.get("remote_port") and lldp_data.get("remote_port"):
                        data["remote_port"] = lldp_data.get("remote_port")
            elif lldp_data:
                data = lldp_data
            else:
                continue
            
            neighbor_name = data.get("neighbor_name", "Unknown")
            neighbor_ip = data.get("neighbor_ip", "")
            remote_port = data.get("remote_port", data.get("remote_port_desc", ""))
            protocol = data.get("protocol", "Unknown")
            
            # Resolve local interface name from index using our mapping
            local_if_name = self._if_index_to_name.get(local_if_index, 
                            self._if_index_to_name.get(str(local_if_index), f"Interface {local_if_index}"))
            
            # Build destination - prefer IP if available, otherwise use port/chassis info
            destination = neighbor_ip if neighbor_ip else data.get("chassis_id", "")
            
            formatted.append({
                "Neighbor Name": neighbor_name,
                "Neighbor ID": neighbor_name,  # CDP/LLDP device ID
                "Remote Port": remote_port if remote_port else "Unknown",
                "Destination IP": neighbor_ip if neighbor_ip else "N/A",
                "Origin Interface": local_if_name,  # Human-readable interface name
                "Local Interface Index": local_if_index,
                "Protocol": protocol,
                "Platform": data.get("platform", ""),
                "Details": f"Discovered via {protocol}"
            })
        
        return formatted
    
    def _format_lldp_value(self, value):
        """
        Format LLDP/CDP value - decode hex strings to readable format.
        """
        if not value:
            return ""
        
        # Already handled by recursive_decode_hex, but let's do preliminary cleaning
        if isinstance(value, str):
            # Handle hex strings
            if value.startswith("0x"):
                from core.utils import decode_hex_string
                return decode_hex_string(value)
            # Skip pure numeric values that don't make sense as text
            if value.isdigit() and len(value) < 3:
                return value
        return value

    def _hex_to_ip(self, hex_value):
        hex_value = hex_value.replace("0x", "")
        # Handle cases where value might not be pure hex or empty
        if not hex_value: return "0.0.0.0"
        try:
            ip_parts = [str(int(hex_value[i:i+2], 16)) for i in range(0, len(hex_value), 2)]
            return ".".join(ip_parts)
        except:
             return hex_value


    def _get_router_details(self, interfaces, neighbors):
        # Map to specific requirements
        # Interfaces: Name, Number, MAC, IP
        # Network Adapters: Name, IP, MAC, Netmask
        # Immediate Neighbors: Dest IP, Local Interface
        
        router_interfaces = []
        adapters = []
        
        for iface in interfaces:
            router_interfaces.append({
                "Interface Name": iface.get("name"),
                "Interface Number": iface.get("index"),
                "MAC Address": iface.get("mac"),
                "IP Address": iface.get("ips")[0]["ip"] if iface.get("ips") else "N/A"
            })
            
            # If it has IP it's an adapter effectively
            if iface.get("ips"):
                for ip_info in iface.get("ips"):
                    adapters.append({
                        "Name": iface.get("name"),
                        "IP Address": ip_info.get("ip"),
                        "MAC Address": iface.get("mac"),
                        "Netmask": ip_info.get("mask")
                    })
        
        return {
            "Interfaces": router_interfaces,
            "Network Adapters": adapters,
            "Immediate Neighbors": neighbors # Needs refinement
        }

    def _get_switch_details(self, interfaces, neighbors):
        ports = []
        adapters = []
        
        for iface in interfaces:
            ports.append({
                "Port name": iface.get("name"),
                "Port number": iface.get("index"),
                "MAC Address": iface.get("mac"),
                "Status": iface.get("status")
            })
             # If it has IP it's an adapter effectively (SVI)
            if iface.get("ips"):
                for ip_info in iface.get("ips"):
                    adapters.append({
                        "Name": iface.get("name"),
                        "IP Address": ip_info.get("ip"),
                        "MAC Address": iface.get("mac"),
                        "Netmask": ip_info.get("mask")
                    })
                    
        return {
            "Ports": ports,
            "Network Adapters": adapters,
            "Neighbors": neighbors
        }

    def _get_firewall_details(self, interfaces, neighbors):
        # Similar to Switch/Router
        ports = []
        adapters = []
        
        for iface in interfaces:
            ports.append({
                "Port name": iface.get("name"),
                "Port number": iface.get("index"),
                "MAC Address": iface.get("mac"),
                "Status": iface.get("status")
            })
            if iface.get("ips"):
                for ip_info in iface.get("ips"):
                    adapters.append({
                        "Name": iface.get("name"),
                        "IP Address": ip_info.get("ip"),
                        "MAC Address": iface.get("mac"),
                        "Netmask": ip_info.get("mask")
                    })

        return {
            "Ports": ports,
            "Network Adapters": adapters,
            "Neighbors": neighbors
        }
