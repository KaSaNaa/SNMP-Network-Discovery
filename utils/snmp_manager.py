import logging, json
from pysnmp.hlapi import CommunityData, UsmUserData, SnmpEngine, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, nextCmd, getCmd
from pysnmp.hlapi.auth import usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol
from pysnmp.hlapi import usmDESPrivProtocol, usm3DESEDEPrivProtocol, usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol

class SNMPManager:
    def __init__(self, version, community=None, user=None, auth_key=None, priv_key=None, auth_protocol=None, priv_protocol=None):
        """
        Initialize the SNMP manager with the given parameters.

        Args:
            version (str): The SNMP version to use.
            community (str, optional): The SNMP community string for SNMPv1/v2c. Defaults to None.
            user (str, optional): The SNMP user for SNMPv3. Defaults to None.
            auth_key (str, optional): The authentication key for SNMPv3. Defaults to None.
            priv_key (str, optional): The privacy key for SNMPv3. Defaults to None.
            auth_protocol (str, optional): The authentication protocol for SNMPv3. Defaults to None.
            priv_protocol (str, optional): The privacy protocol for SNMPv3. Defaults to None.
        """
        self.version = version
        self.community = community
        self.user = user
        self.auth_key = auth_key
        self.priv_key = priv_key
        self.auth_protocol = auth_protocol
        self.priv_protocol = priv_protocol

        # Validate SNMPv3 parameters
        if self.version == 3:
            self.__validate_snmpv3_params()

        logging.basicConfig(
            filename='logs/snmp_errors.log',  
            level=logging.ERROR,
            format='%(asctime)s %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def __validate_snmpv3_params(self):
        """
        Validate SNMPv3 parameters to ensure they are correct objects required by UsmUserData.
        """
        if not self.user or not self.auth_key or not self.priv_key or not self.auth_protocol or not self.priv_protocol:
            raise ValueError("User, auth_key, priv_key, auth_protocol, and priv_protocol are required for SNMPv3")

        valid_auth_protocols = [usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol]
        valid_priv_protocols = [usmDESPrivProtocol, usm3DESEDEPrivProtocol, usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol]

        if self.auth_protocol not in valid_auth_protocols:
            raise ValueError(f"Invalid auth_protocol: {self.auth_protocol}. Must be one of {valid_auth_protocols}")

        if self.priv_protocol not in valid_priv_protocols:
            raise ValueError(f"Invalid priv_protocol: {self.priv_protocol}. Must be one of {valid_priv_protocols}")


    def snmp_discovery(self, target, base_oid='1.3.6.1.2.1.1', use_next_cmd=True):
        """
        Perform SNMP discovery on a target device.
        Args:
            target (str): The IP address or hostname of the target device.
            base_oid (str, optional): The base OID to start the discovery from. Defaults to '1.3.6.1.2.1.1'.
            use_next_cmd (bool, optional): Whether to use the SNMP nextCmd (True) or getCmd (False). Defaults to True.
        Returns:
            list: A list of tuples containing OID and value pairs discovered.
        Raises:
            ValueError: If required parameters for the specified SNMP version are missing or if an invalid SNMP version is specified.
        """
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
    
        cmd = nextCmd if use_next_cmd else getCmd
    
        for errorIndication, errorStatus, errorIndex, varBinds in cmd(
            SnmpEngine(),
            user_data,
            UdpTransportTarget((target, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False if use_next_cmd else True,
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
        """
        Retrieves SNMP neighbors for a given IP address using LLDP and CDP protocols.

        Args:
            ip (str): The IP address of the device to query for neighbors.

        Returns:
            list: A list of neighbors discovered via SNMP using LLDP and CDP protocols.
        """
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
        """
        Retrieves the local ports and their descriptions from the target device using SNMP.

        Args:
            target (str): The IP address or hostname of the target device.

        Returns:
            dict: A dictionary where the keys are port indices and the values are port descriptions.

        Raises:
            ValueError: If required SNMP parameters are missing or if an invalid SNMP version is specified.

        Notes:
            - For SNMPv1 and SNMPv2c, the community string must be provided.
            - For SNMPv3, the user, auth_key, priv_key, auth_protocol, and priv_protocol must be provided.
            - The function uses the OID ".1.3.6.1.2.1.31.1.1.1.1" to retrieve interface descriptions.
        """
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
    
    
    def recursive_discovery(self, ip, discovered_devices=None, discovered_ips=None):
        """
        Recursively discovers network devices starting from a given IP address.

        Args:
            ip (str): The IP address to start the discovery from.
            discovered_devices (dict, optional): A dictionary to store discovered devices and their details.
                                                 Defaults to None.
            discovered_ips (set, optional): A set to keep track of discovered IP addresses to avoid loops.
                                            Defaults to None.

        Returns:
            dict: A dictionary containing the discovered devices with their hostnames, neighbors, and ports.

        The structure of the returned dictionary is as follows:
            {
                "ip_address": {
                    "hostname": "hostname",
                    "neighbors": {
                        "neighbor_ip": {
                            "local_interface": "local_port_name",
                            "remote_interface": "remote_interface_name",
                            "details": { ... }  # Recursive structure for neighbor's neighbors
                        },
                        ...
                    },
                    "ports": {
                        "port_index": "port_name",
                        ...
                },
                ...
        """
        if discovered_devices is None:
            discovered_devices = {}
        if discovered_ips is None:
            discovered_ips = set()

        print(f"Discovering neighbors for IP: {ip}")

        # Add the current IP to the set of discovered IPs
        discovered_ips.add(ip)

        # Get the hostname of the current IP
        hostname_result = self.snmp_discovery(ip, "1.3.6.1.2.1.1.5.0", False)
        hostname = hostname_result[0][1] if hostname_result else "Unknown"

        # Get the neighbors and local ports
        neighbors = self.get_snmp_neighbors(ip)
        ports = self.get_local_ports(ip)

        # Store the neighbors, ports, and hostname for the current IP
        discovered_devices[ip] = {
            "hostname": hostname,
            "neighbors": {},
            "ports": ports
        }

        # Iterate through neighbors to identify connections
        for oid, value in neighbors:
            if oid.startswith("SNMPv2-SMI::enterprises.9.9.23.1.2.1.1.4"):
                neighbor_ip = self.__hex_to_ip(value)
                local_port_oid = oid.split(".")[-1]  # Get port index from OID
                local_port_name = ports.get(local_port_oid, "Unknown")
                # print(f"Local Port: {local_port_oid}:{local_port_name}")
                # Get the remote interface name (via LLDP/CDP, or mock if unavailable)
                remote_interface = self.get_remote_interface(neighbor_ip, ip, local_port_oid)

                if neighbor_ip not in discovered_ips:
                    discovered_ips.add(neighbor_ip)

                    # Recursively discover neighbors of the neighbor
                    discovered_devices[ip]["neighbors"][neighbor_ip] = {
                        "local_interface": local_port_name,
                        "remote_interface": remote_interface,
                        "details": self.recursive_discovery(neighbor_ip, {}, discovered_ips)[neighbor_ip]
                    }

        return discovered_devices
    
    def __is_protocol_not_enabled(self, result):
        return result and result[0][1] == "No Such Instance currently exists at this OID"

    def get_remote_interface(self, neighbor_ip, source_ip, local_port_oid):
        """
        Retrieves the remote interface description using SNMP discovery via LLDP or CDP.
        This method attempts to discover the remote interface description by querying the
        LLDP (Link Layer Discovery Protocol) OID first. If the LLDP query fails or returns
        no result, it falls back to querying the CDP (Cisco Discovery Protocol) OID.
        Args:
            neighbor_ip (str): The IP address of the neighboring device.
            source_ip (str): The IP address of the source device.
            local_port_oid (str): The OID of the local port.
        Returns:
            str: The description of the remote interface if found, otherwise "Unknown".
        """
        # LLDP OID
        lldp_remote_oid = f"1.0.8802.1.1.2.1.4.1.1.7.{local_port_oid}"
        
        # CDP OID
        cdp_remote_oid = f".1.3.6.1.4.1.9.9.23.1.2.1.1.6.{local_port_oid}"
        
        # Try LLDP first
        remote_interface_result = self.snmp_discovery(neighbor_ip, lldp_remote_oid, False)
        
        if self.__is_protocol_not_enabled(remote_interface_result):
            print("LLDP is not enabled on the interfaces of the target device!")
            return "LLDP is not enabled on the interface."
        
        # Fallback to CDP if LLDP fails
        if not remote_interface_result:
            remote_interface_result = self.snmp_discovery(neighbor_ip, cdp_remote_oid, False)
        
            if self.__is_protocol_not_enabled(remote_interface_result):
                print("CDP is not enabled on the interfaces of the target device!")
                return "CDP is not enabled on the interface."
        else:
            # If both LLDP and CDP fail, return 'Unknown'
            return "Unknown"
        
        if remote_interface_result and len(remote_interface_result) > 0 and len(remote_interface_result[0]) > 1:
            print(json.dumps(remote_interface_result, indent=4))
            return remote_interface_result[0][1]
        else:
            return "Unknown"


    def __hex_to_ip(self, hex_value):
        """
        Convert a hexadecimal string to an IP address.

        Args:
            hex_value (str): The hexadecimal string representing the IP address.

        Returns:
            str: The converted IP address in dotted-decimal format.
        """
        # Convert hex string to IP address
        hex_value = hex_value.replace("0x", "")
        ip_parts = [str(int(hex_value[i:i+2], 16)) for i in range(0, len(hex_value), 2)]
        return ".".join(ip_parts)