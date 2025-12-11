import os
import logging
import re

def ensure_directory_exists(file_path):
    """
    Ensures that the directory for the given file path exists.
    """
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as e:
            logging.error(f"Error creating directory {directory}: {e}")

def is_printable_ascii(s):
    """Check if a string contains mostly printable ASCII characters."""
    if not s:
        return False
    printable_count = sum(1 for c in s if 32 <= ord(c) <= 126 or c in '\r\n\t')
    return printable_count / len(s) > 0.7  # At least 70% printable

def decode_hex_string(value):
    """
    Detects if a string is hex-encoded (starts with 0x) and decodes it to readable format.
    Handles various formats: MAC addresses, IP addresses, and ASCII text.
    """
    if not isinstance(value, str):
        return value
    
    # Handle 0x prefixed hex strings
    if value.startswith("0x"):
        try:
            hex_str = value[2:]
            
            # Handle empty hex string
            if not hex_str:
                return value
            
            # Pad if odd length
            if len(hex_str) % 2 == 1:
                hex_str = '0' + hex_str
            
            decoded_bytes = bytes.fromhex(hex_str)
            
            # Check for MAC Address (6 bytes)
            if len(decoded_bytes) == 6:
                return ":".join(f"{b:02x}" for b in decoded_bytes)
            
            # Check for IPv4 (4 bytes) - all bytes should be valid IP octets
            if len(decoded_bytes) == 4:
                return ".".join(str(b) for b in decoded_bytes)
            
            # Try to decode as UTF-8 text
            try:
                decoded_text = decoded_bytes.decode('utf-8')
                # Check if result is mostly printable ASCII
                if is_printable_ascii(decoded_text):
                    # Clean up any control characters except newlines
                    cleaned = ''.join(c if (32 <= ord(c) <= 126 or c in '\r\n\t') else '' for c in decoded_text)
                    return cleaned.strip()
            except UnicodeDecodeError:
                pass
            
            # Try latin-1 (1-to-1 byte mapping) as fallback for text
            try:
                decoded_text = decoded_bytes.decode('latin-1')
                if is_printable_ascii(decoded_text):
                    cleaned = ''.join(c if (32 <= ord(c) <= 126 or c in '\r\n\t') else '' for c in decoded_text)
                    return cleaned.strip()
            except:
                pass
            
            # If it's a long hex string that couldn't be decoded as text, 
            # try to format it nicely or return a summary
            if len(hex_str) > 24:  # More than 12 bytes
                # Return as formatted MAC-style for readability
                return ":".join(hex_str[i:i+2] for i in range(0, min(24, len(hex_str)), 2)) + "..."
            else:
                # Format as colon-separated bytes
                return ":".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
                
        except Exception as e:
            logging.debug(f"Failed to decode hex string {value}: {e}")
            return value
    
    return value

def recursive_decode_hex(data):
    """
    Recursively traverses a dictionary or list and decodes any hex strings found.
    """
    if isinstance(data, dict):
        return {k: recursive_decode_hex(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [recursive_decode_hex(item) for item in data]
    elif isinstance(data, str):
        return decode_hex_string(data)
    else:
        return data


def classify_device_type(sys_info, interfaces=None):
    """
    Classify a network device as Router, Switch, Firewall, or Unknown based on
    multiple indicators with confidence scoring.
    
    Args:
        sys_info: Dictionary containing system information (description, object_id, services, etc.)
        interfaces: List of interface dictionaries (optional, for additional classification hints)
    
    Returns:
        tuple: (device_type, confidence, indicators)
            - device_type: "Router", "Switch", "Firewall", or "Unknown"
            - confidence: "High", "Medium", or "Low"
            - indicators: List of strings explaining the classification
    """
    scores = {"Router": 0, "Switch": 0, "Firewall": 0}
    indicators = []
    
    description = sys_info.get("description", "").lower()
    object_id = sys_info.get("object_id", "")
    services_val = sys_info.get("services", "0")
    device_name = sys_info.get("name", "").lower()
    
    # 1. First check description for L2/L3 indicators - VERY important for IOS devices
    # This helps distinguish between IOS routers and IOS switches that share same OID
    if "l2-" in description or "-l2" in description or "linuxl2" in description or "_l2" in description:
        scores["Switch"] += 35
        indicators.append("Description contains 'L2' indicator (Layer 2 switch)")
    elif "l3-" in description or "-l3" in description:
        scores["Router"] += 15
        indicators.append("Description contains 'L3' indicator")
    
    # 2. Analyze sysObjectID (Enterprise OIDs)
    # Cisco Enterprise OID: 1.3.6.1.4.1.9
    if object_id:
        # Cisco Switches - check these FIRST (more specific OIDs)
        cisco_switch_oids = [
            "1.3.6.1.4.1.9.1.516",    # Cisco Catalyst 3750
            "1.3.6.1.4.1.9.1.696",    # Cisco Catalyst 3750-E
            "1.3.6.1.4.1.9.1.1208",   # Cisco Catalyst 2960
            "1.3.6.1.4.1.9.1.1016",   # Cisco Catalyst 3560
            "1.3.6.1.4.1.9.1.1227",   # Cisco Nexus
            "1.3.6.1.4.1.9.1.2066",   # Cisco Catalyst 9000
            "1.3.6.1.4.1.9.1.559",    # Cisco Catalyst 3550
            "1.3.6.1.4.1.9.1.366",    # Cisco Catalyst 2950
            "1.3.6.1.4.1.9.1.695",    # Cisco Catalyst 2960
            "1.3.6.1.4.1.9.1.950",    # Cisco Catalyst 2960-S
            "1.3.6.1.4.1.9.1.1745",   # Cisco Catalyst 3850
            "1.3.6.1.4.1.9.1.2494",   # Cisco Catalyst 9200
            "1.3.6.1.4.1.9.1.2495",   # Cisco Catalyst 9300
        ]
        
        # Cisco Routers - specific router OIDs
        cisco_router_oids = [
            "1.3.6.1.4.1.9.1.122",    # Cisco 2600
            "1.3.6.1.4.1.9.1.208",    # Cisco 3600
            "1.3.6.1.4.1.9.1.283",    # Cisco 7200
            "1.3.6.1.4.1.9.1.46",     # Cisco 4000
            "1.3.6.1.4.1.9.1.620",    # Cisco ISR
            "1.3.6.1.4.1.9.1.1045",   # Cisco CSR 1000v
            "1.3.6.1.4.1.9.1.896",    # Cisco ISR G2
            "1.3.6.1.4.1.9.1.1041",   # Cisco ISR 4000
            "1.3.6.1.4.1.9.1.2137",   # Cisco ISR 1000
        ]
        
        # Cisco Firewalls/ASA
        cisco_firewall_oids = [
            "1.3.6.1.4.1.9.1.417",    # Cisco ASA
            "1.3.6.1.4.1.9.1.670",    # Cisco FWSM
            "1.3.6.1.4.1.9.1.669",    # Cisco PIX
            "1.3.6.1.4.1.9.1.2228",   # Cisco Firepower
            "1.3.6.1.4.1.9.1.745",    # Cisco ASA 5500
        ]
        
        oid_matched = False
        
        for oid in cisco_firewall_oids:
            if object_id.startswith(oid):
                scores["Firewall"] += 40
                indicators.append(f"OID match: Cisco Firewall ({oid})")
                oid_matched = True
                break
        
        if not oid_matched:
            for oid in cisco_switch_oids:
                if object_id.startswith(oid):
                    scores["Switch"] += 35
                    indicators.append(f"OID match: Cisco Switch ({oid})")
                    oid_matched = True
                    break
        
        if not oid_matched:
            for oid in cisco_router_oids:
                if object_id.startswith(oid):
                    scores["Router"] += 35
                    indicators.append(f"OID match: Cisco Router ({oid})")
                    oid_matched = True
                    break
        
        # Generic Cisco IOS OID - don't assign strong score, let other indicators decide
        if not oid_matched and object_id.startswith("1.3.6.1.4.1.9.1.1"):
            # This is the generic IOS OID - could be router or switch
            # Don't add points here, let description/interface analysis decide
            indicators.append("Generic Cisco IOS device (OID 1.3.6.1.4.1.9.1.1)")
        
        # Other vendors
        if "1.3.6.1.4.1.2636" in object_id:  # Juniper
            indicators.append("Juniper device detected")
            if "router" in description or "mx" in description:
                scores["Router"] += 20
            elif "ex" in description or "switch" in description:
                scores["Switch"] += 20
            elif "srx" in description:
                scores["Firewall"] += 20
        elif "1.3.6.1.4.1.12356" in object_id:  # Fortinet
            scores["Firewall"] += 40
            indicators.append("Fortinet device detected (likely firewall)")
        elif "1.3.6.1.4.1.25461" in object_id:  # Palo Alto
            scores["Firewall"] += 40
            indicators.append("Palo Alto device detected (likely firewall)")
        elif "1.3.6.1.4.1.25506" in object_id:  # H3C/HP
            indicators.append("H3C/HP device detected")
        elif "1.3.6.1.4.1.674" in object_id:  # Dell
            indicators.append("Dell device detected")
    
    # 3. Analyze sysServices (Layer information)
    try:
        services = int(services_val)
        # Services value is a sum of powers of 2:
        # Layer 1 (physical) = 1
        # Layer 2 (datalink/switch) = 2  
        # Layer 3 (network/router) = 4
        # Layer 4 (transport) = 8
        # Layer 7 (application) = 64
        
        is_l2 = bool(services & 2)
        is_l3 = bool(services & 4)
        is_l4 = bool(services & 8)
        is_l7 = bool(services & 64)
        
        if is_l3 and is_l4:
            # Could be router, L3 switch, or firewall
            scores["Router"] += 10
            scores["Switch"] += 5  # L3 switches also have this
            scores["Firewall"] += 8
            indicators.append(f"sysServices={services}: L3+L4 (routing capable)")
        elif is_l3 and not is_l2:
            scores["Router"] += 20
            indicators.append(f"sysServices={services}: L3 only (router)")
        elif is_l2 and not is_l3:
            scores["Switch"] += 30
            indicators.append(f"sysServices={services}: L2 only (Layer 2 switch)")
        elif is_l2 and is_l3:
            # L3 switch or router - need other indicators to decide
            indicators.append(f"sysServices={services}: L2+L3 (L3 switch or router)")
            scores["Switch"] += 8
            scores["Router"] += 8
        
        if is_l7:
            scores["Firewall"] += 5
            indicators.append(f"sysServices includes L7 (application layer)")
            
    except (ValueError, TypeError):
        pass
    
    # 4. Analyze sysDescr keywords - Moderate reliability
    # Firewall keywords (check first as they're more specific)
    firewall_keywords = [
        "firewall", "asa", "pix", "fortigate", "fortinet", "palo alto",
        "checkpoint", "sophos", "sonicwall", "watchguard", "firepower",
        "utm", "ngfw", "security appliance"
    ]
    for keyword in firewall_keywords:
        if keyword in description:
            scores["Firewall"] += 25
            indicators.append(f"Keyword match: '{keyword}' in description (firewall)")
            break
    
    # Router keywords
    router_keywords = [
        "router", "ios xr", "junos", "isr", "csr1000", "7200", "3900",
        "2900", "2800", "1900", "asr"
    ]
    for keyword in router_keywords:
        if keyword in description:
            scores["Router"] += 20
            indicators.append(f"Keyword match: '{keyword}' in description (router)")
            break
    
    # Switch keywords
    switch_keywords = [
        "switch", "catalyst", "nexus", "sg300", "sg500", "procurve",
        "aruba", "powerconnect", "ex2200", "ex3", "ex4", "c2960", "c3560",
        "c3750", "c3850", "c9200", "c9300", "layer 2", "layer2"
    ]
    for keyword in switch_keywords:
        if keyword in description:
            scores["Switch"] += 20
            indicators.append(f"Keyword match: '{keyword}' in description (switch)")
            break
    
    # 5. Analyze device name - useful hint
    if device_name:
        name_lower = device_name.lower()
        if any(x in name_lower for x in ["fw", "firewall", "asa", "pix"]):
            scores["Firewall"] += 15
            indicators.append(f"Device name suggests firewall")
        elif any(x in name_lower for x in ["rtr", "router", "rt-", "-rt", "gw", "gateway"]):
            scores["Router"] += 15
            indicators.append(f"Device name suggests router")
        elif any(x in name_lower for x in ["sw", "switch", "cat", "nexus"]):
            scores["Switch"] += 15
            indicators.append(f"Device name suggests switch")
    
    # 6. Analyze interfaces (if provided) - Important for distinguishing switch vs router
    if interfaces:
        has_routing_interfaces = False
        has_wan_interfaces = False
        has_vlan_interfaces = False
        ports_without_ip = 0
        ports_with_ip = 0
        total_ports = len(interfaces)
        
        for iface in interfaces:
            name = iface.get("name", "").lower()
            ips = iface.get("ips", [])
            
            # Check for VLAN/SVI interfaces (strong switch indicator)
            if any(x in name for x in ["vlan", "svi", "bvi"]):
                has_vlan_interfaces = True
            
            # Check for routing-specific interfaces
            if any(x in name for x in ["serial", "tunnel", "gre", "wan", "pos", "atm"]):
                has_routing_interfaces = True
                has_wan_interfaces = True
            
            # Count ports with/without IPs
            if ips:
                ports_with_ip += 1
            else:
                if not any(x in name for x in ["null", "loopback", "lo"]):
                    ports_without_ip += 1
        
        # VLAN interfaces are strong switch indicators
        if has_vlan_interfaces:
            scores["Switch"] += 20
            indicators.append("Has VLAN/SVI interfaces (typical of switches)")
        
        # WAN/Serial interfaces suggest router
        if has_wan_interfaces:
            scores["Router"] += 20
            indicators.append("Has WAN/Serial interfaces (typical of routers)")
        
        # Many ports without IPs is typical of switches
        if total_ports > 4 and ports_without_ip > (total_ports * 0.6):
            scores["Switch"] += 15
            indicators.append(f"Most interfaces have no IP ({ports_without_ip}/{total_ports}) - typical of switch")
        
        # Few interfaces all with IPs is more typical of routers
        if total_ports <= 8 and ports_with_ip > 0 and ports_without_ip <= 2:
            scores["Router"] += 10
            indicators.append(f"Few interfaces with IPs - typical of router")
    
    # Determine the winner
    max_score = max(scores.values())
    
    if max_score == 0:
        return ("Unknown", "Low", ["Insufficient information for classification"])
    
    # Find device type with highest score
    device_type = max(scores, key=scores.get)
    
    # Determine confidence based on score difference
    sorted_scores = sorted(scores.values(), reverse=True)
    score_diff = sorted_scores[0] - sorted_scores[1] if len(sorted_scores) > 1 else max_score
    
    if max_score >= 45 and score_diff >= 20:
        confidence = "High"
    elif max_score >= 30 or score_diff >= 15:
        confidence = "Medium"
    else:
        confidence = "Low"
    
    return (device_type, confidence, indicators)