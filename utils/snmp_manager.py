import json
from pysnmp.hlapi import *
import logging

class SNMPManager:
    def __init__(self, version, community=None, user=None, auth_key=None, priv_key=None, auth_protocol=None, priv_protocol=None):
        self.version = version
        self.community = community
        self.user = user
        self.auth_key = auth_key
        self.priv_key = priv_key
        self.auth_protocol = auth_protocol
        self.priv_protocol = priv_protocol
        logging.basicConfig(
            filename='logs/snmp_errors.log',  
            level=logging.ERROR,
            format='%(asctime)s %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def snmp_discovery(self, target, base_oid='1.3.6.1.2.1.1'): # .1.3.6.1.2.1.2.2.1 for ifTable
        results = []
        if self.version == 1 or self.version == 2:
            if not self.community:
                raise ValueError("Community string is required for SNMPv1 and SNMPv2c")
            user_data = CommunityData(self.community, mpModel=0 if self.version == 1 else 1)
        elif self.version == 3:
            if not self.user or not self.auth_key or not self.priv_key or not self.auth_protocol or not self.priv_protocol:
                raise ValueError("User, auth_key, priv_key, auth_protocol, and priv_protocol are required for SNMPv3")
            user_data = UsmUserData(
                self.user,
                self.auth_key,
                self.priv_key,
                authProtocol=self.auth_protocol,
                privProtocol=self.priv_protocol,
            )
        else:
            raise ValueError("Invalid SNMP version. Must be 1, 2, or 3.")

        for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
            SnmpEngine(),
            user_data,
            UdpTransportTarget((target, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if errorIndication or errorStatus:
                # Log errors into a log file
                if errorIndication:
                    logging.error(f'Error Indication: {errorIndication}')
                if errorStatus:
                    logging.error(f'Error Status: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
                continue
            else:
                for varBind in varBinds:
                    oid_str, value_str = varBind
                    results.append((oid_str.prettyPrint(), value_str.prettyPrint()))
        return results

    def get_snmp_neighbors(self, ip):
        neighbors = []

        def get_lldp_neighbors():
            lldp_oid = "1.0.8802.1.1.2.1.4"
            return self.snmp_discovery(ip, lldp_oid)

        def get_cdp_neighbors():
            cdp_oid = ".1.3.6.1.4.1.9.9.23.1.2.1"
            return self.snmp_discovery(ip, cdp_oid)

        neighbors.extend(get_lldp_neighbors())
        neighbors.extend(get_cdp_neighbors())

        return neighbors

    def get_local_ports(self, target):
        local_ports = {}
        if_descr_oid = ".1.3.6.1.2.1.31.1.1.1.1"

        if self.version == 1 or self.version == 2:
            if not self.community:
                raise ValueError("Community string is required for SNMPv1 and SNMPv2c")
            user_data = CommunityData(self.community, mpModel=0 if self.version == 1 else 1)
        elif self.version == 3:
            if not self.user or not self.auth_key or not self.priv_key or not self.auth_protocol or not self.priv_protocol:
                raise ValueError("User, auth_key, priv_key, auth_protocol, and priv_protocol are required for SNMPv3")
            user_data = UsmUserData(
                self.user,
                self.auth_key,
                self.priv_key,
                authProtocol=self.auth_protocol,
                privProtocol=self.priv_protocol,
            )
        else:
            raise ValueError("Invalid SNMP version. Must be 1, 2, or 3.")

        for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
            SnmpEngine(),
            user_data,
            UdpTransportTarget((target, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(if_descr_oid)),
            lexicographicMode=False,
        ):
            if errorIndication:
                print(f"Error: {errorIndication}")
                break
            elif errorStatus:
                print(
                    "%s at %s"
                    % (
                        errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
                    )
                )
                break
            elif varBinds:
                for varBind in varBinds:
                    oid, value = varBind
                    oid_str = oid.prettyPrint()
                    value_str = value.prettyPrint()
                    port_index = oid_str.split(".")[-1]
                    local_ports[port_index] = value_str

        return local_ports
    
    def recursive_discovery(self, ip, discovered_devices=None):
        if discovered_devices is None:
            discovered_devices = {}
    
        # Print the current IP being used to get neighbors
        print(f"Discovering neighbors for IP: {ip}")
    
        neighbors = self.get_snmp_neighbors(ip)
        for oid, value in neighbors:
            if oid.startswith("SNMPv2-SMI::enterprises.9.9.23.1.2.1.1.4"):
                neighbor_ip = self.hex_to_ip(value)
                print(f"Found neighbor: {neighbor_ip}")
                if neighbor_ip not in discovered_devices:
                    discovered_devices[neighbor_ip] = oid
                    # Recursively discover neighbors of the neighbor
                    self.recursive_discovery(neighbor_ip, discovered_devices)
                    
        return discovered_devices

    def hex_to_ip(self, hex_value):
        # Convert hex string to IP address
        hex_value = hex_value.replace("0x", "")
        ip_parts = [str(int(hex_value[i:i+2], 16)) for i in range(0, len(hex_value), 2)]
        return ".".join(ip_parts)