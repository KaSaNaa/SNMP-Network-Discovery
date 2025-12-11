import json
from core.snmp_manager import SNMPManager

class DeviceDiscovery:
    def __init__(self, ip, version=2, community='public', user=None, auth_key=None, priv_key=None, auth_protocol=None, priv_protocol=None):
        self.ip = ip
        self.snmp_manager = SNMPManager(version, community, user, auth_key, priv_key, auth_protocol, priv_protocol)
        self.device_data = {}

    async def discover(self):
        """
        Orchestrate the discovery process.
        """
        # 1. Validate Reachability
        if not await self.snmp_manager.validate_snmp_reachability(self.ip):
            return {"error": f"Device {self.ip} is not reachable via SNMP or credentials are wrong."}

        # 2. Basic System Info
        system_info = await self.snmp_manager.get_system_info(self.ip)
        
        # 3. Fetch Interfaces/Ports
        interfaces = await self.snmp_manager.get_full_interface_details(self.ip)
        
        # 4. Determine Device Type using intelligent classification
        from core.utils import classify_device_type
        device_type, confidence, indicators = classify_device_type(system_info, interfaces)
        
        # 5. Extract device type description from sysDescr (keep as additional info)
        device_type_description = self._extract_device_type_from_description(system_info.get("description", ""))
        
        # 6. Fetch Neighbors (Generic)
        neighbors_raw = await self.snmp_manager.get_snmp_neighbors(self.ip)
        neighbors_formatted = self._format_neighbors(neighbors_raw)

        # 7. Construct Final JSON
        self.device_data = {
            "Device Name": system_info.get("name", "Unknown"),
            "Device Type": device_type,
            "Device Type Confidence": confidence,
            "Device Type Indicators": indicators,
            "Device Type Description": device_type_description,
            "IP Address": self.ip,
            "Manufacturer": self._guess_manufacturer(system_info.get("description", ""), system_info.get("object_id", "")),
            "Model Number": self._extract_model(system_info.get("description", "")),
            "System OID": system_info.get("object_id", "Unknown"),
            "Description": system_info.get("description", "Unknown"),
            "Serial Number": "Unknown", # Requires EntPhysicalTable or vendor specific OID
            "Details": {} # Type specific
        }
        
        # Add Type specific details
        self.device_data["Details"] = {
            "Interfaces": interfaces,
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

    def _extract_model(self, description):
        # Very rough extraction, usually model is first or second word after manufacturer
        # Or parse standard strings
        return "Unknown (Parsed from sysDescr)"

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
        
        # Convert neighbor_data dict to formatted list
        for key, data in neighbor_data.items():
            neighbor_name = data.get("neighbor_name", "Unknown")
            neighbor_ip = data.get("neighbor_ip", "")
            remote_port = data.get("remote_port", data.get("remote_port_desc", ""))
            protocol = data.get("protocol", "Unknown")
            
            # Build destination - prefer IP if available, otherwise use port/chassis info
            destination = neighbor_ip if neighbor_ip else data.get("chassis_id", "")
            
            formatted.append({
                "Neighbor Name": neighbor_name,
                "Remote Port": remote_port if remote_port else "Unknown",
                "Destination IP": neighbor_ip if neighbor_ip else "N/A",
                "Local Interface Index": data.get("local_interface", "Unknown"),
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
