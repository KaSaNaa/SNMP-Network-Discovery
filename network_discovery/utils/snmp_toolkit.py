from pysnmp.hlapi import (
    SnmpEngine,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    nextCmd
)
from typing import List, Tuple, Dict

class NetworkDiscovery:
    def __init__(self):
        pass

    def snmp_discovery(self, target: str, user: str, auth_key: str, priv_key: str, auth_protocol, priv_protocol, base_oid: str) -> List[Tuple[str, str]]:
        """
        Perform SNMP discovery on a target device.

        This function uses SNMPv3 to query a target device and retrieve information
        based on the provided base OID. The results are returned as a list of tuples,
        where each tuple contains the OID and its corresponding value.

        Parameters:
        target (str): The IP address or hostname of the target device.
        user (str): The SNMPv3 username.
        auth_key (str): The SNMPv3 authentication key.
        priv_key (str): The SNMPv3 privacy key.
        auth_protocol (Object): The SNMPv3 authentication protocol (e.g., usmHMACSHAAuthProtocol).
        priv_protocol (Object): The SNMPv3 privacy protocol (e.g., usmAesCfb128Protocol).
        base_oid (str): The base OID to start the SNMP walk.

        Returns:
        List[Tuple[str, str]]: A list of tuples containing OIDs and their values.
        """
        results = []

        for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
            SnmpEngine(),
            UsmUserData(
                user,
                auth_key,
                priv_key,
                authProtocol=auth_protocol,
                privProtocol=priv_protocol,
            ),
            UdpTransportTarget((target, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        ):
            if errorIndication:
                print(f"SNMP error: {errorIndication}")
                break

            if errorStatus:
                print(
                    f"SNMP error: {errorStatus.prettyPrint()} at "
                    f"{errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
                )
                break

            for varBind in varBinds:
                oid, value = varBind
                results.append((oid.prettyPrint(), value.prettyPrint()))

        return results

    def get_snmp_neighbors(self, ip: str, user: str, auth_key: str, priv_key: str, auth_protocol, priv_protocol) -> List[Tuple[str, str]]:
        """
        Retrieve SNMP neighbors using LLDP and CDP protocols.

        Parameters:
        ip (str): The IP address of the device to query.
        user (str): The SNMPv3 username.
        auth_key (str): The SNMPv3 authentication key.
        priv_key (str): The SNMPv3 privacy key.
        auth_protocol (Object): The SNMPv3 authentication protocol (e.g., usmHMACSHAAuthProtocol).
        priv_protocol (Object): The SNMPv3 privacy protocol (e.g., usmAesCfb128Protocol).

        Returns:
        List[Tuple[str, str]]: A list of neighbors discovered via LLDP and CDP.
        """
        neighbors = []

        # Fetch LLDP neighbors
        lldp_oid = "1.0.8802.1.1.2.1.4"
        neighbors.extend(
            self.snmp_discovery(ip, user, auth_key, priv_key, auth_protocol, priv_protocol, lldp_oid)
        )

        # Fetch CDP neighbors
        cdp_oid = "1.3.6.1.4.1.9.9.23.1.2.1"
        neighbors.extend(
            self.snmp_discovery(ip, user, auth_key, priv_key, auth_protocol, priv_protocol, cdp_oid)
        )

        return neighbors

    def get_local_ports(self, target: str, user: str, auth_key: str, priv_key: str, auth_protocol, priv_protocol) -> Dict[str, str]:
        """
        Retrieve local port descriptions from a target SNMP-enabled device.

        Parameters:
        target (str): The IP address or hostname of the target SNMP device.
        user (str): The SNMPv3 username.
        auth_key (str): The SNMPv3 authentication key.
        priv_key (str): The SNMPv3 privacy key.
        auth_protocol (Object): The SNMPv3 authentication protocol (e.g., usmHMACSHAAuthProtocol).
        priv_protocol (Object): The SNMPv3 privacy protocol (e.g., usmAesCfb128Protocol).

        Returns:
        Dict[str, str]: A dictionary where keys are port indices (as strings) and values are port descriptions.
        """
        local_ports = {}
        if_descr_oid = "1.3.6.1.2.1.31.1.1.1.1"

        for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
            SnmpEngine(),
            UsmUserData(
                user,
                auth_key,
                priv_key,
                authProtocol=auth_protocol,
                privProtocol=priv_protocol,
            ),
            UdpTransportTarget((target, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(if_descr_oid)),
            lexicographicMode=False,
        ):
            if errorIndication:
                print(f"Error: {errorIndication}")
                break

            if errorStatus:
                print(
                    f"SNMP error: {errorStatus.prettyPrint()} at "
                    f"{errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
                )
                break

            for varBind in varBinds:
                oid, value = varBind
                port_index = oid.prettyPrint().split(".")[-1]
                local_ports[port_index] = value.prettyPrint()

        return local_ports

