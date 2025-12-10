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
        
        # 3. Determine Device Type
        device_type = self._classify_device(system_info)
        
        # 4. Fetch Interfaces/Ports
        interfaces = await self.snmp_manager.get_full_interface_details(self.ip)
        
        # 5. Fetch Neighbors (Generic)
        neighbors_raw = await self.snmp_manager.get_snmp_neighbors(self.ip)
        neighbors_formatted = self._format_neighbors(neighbors_raw)

        # 6. Construct Final JSON
        self.device_data = {
            "Device Name": system_info.get("name", "Unknown"),
            "Device type": device_type,
            "IP Address": self.ip,
            "Manufacturer": self._guess_manufacturer(system_info.get("description", "")),
            "Model Number": self._extract_model(system_info.get("description", "")),
            "System OID": system_info.get("object_id", "Unknown"),
            "Description": system_info.get("description", "Unknown"),
            "Serial Number": "Unknown", # Requires EntPhysicalTable or vendor specific OID
            "Details": {} # Type specific
        }
        
        # Add Type specific details
        if device_type == "Router":
            self.device_data["Details"] = self._get_router_details(interfaces, neighbors_formatted)
        elif device_type == "Switch":
            self.device_data["Details"] = self._get_switch_details(interfaces, neighbors_formatted)
        elif device_type == "Firewall":
            self.device_data["Details"] = self._get_firewall_details(interfaces, neighbors_formatted)
        else:
            # Fallback or Generic
            self.device_data["Details"] = {
                "Interfaces": interfaces,
                "Neighbors": neighbors_formatted
            }

        return self.device_data

    def _classify_device(self, sys_info):
        """
        Classifies device usage sysServices and sysDescr.
        """
        services_val = sys_info.get("services", "0")
        description = sys_info.get("description", "").lower()
        
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

    def _guess_manufacturer(self, description):
        description = description.lower()
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
        formatted = []
        for oid, value in neighbors_raw:
            # Check for Cisco CDP Neighbor IP (Hex)
            # OID usually contains ...9.9.23.1.2.1.1.4...
            if "9.9.23.1.2.1.1.4" in oid or "1.3.6.1.4.1.9.9.23.1.2.1.1.4" in oid:
                try:
                    neighbor_ip = self._hex_to_ip(value)
                except ValueError:
                    neighbor_ip = value # Fallback if not hex
                
                formatted.append({
                    "Neighbor name": "Unknown (CDP)",
                    "Destination IP network": neighbor_ip,
                    "Details": "Discovered via CDP"
                })
            
            # Check for LLDP
            # 1.0.8802.1.1.2.1.4...
            elif "1.0.8802.1.1.2.1.4" in oid:
                 formatted.append({
                    "Neighbor name": "Unknown (LLDP)",
                    "Destination IP network": value, # LLDP might return clean IP or bytes
                    "Details": "Discovered via LLDP"
                })
            
        return formatted

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
