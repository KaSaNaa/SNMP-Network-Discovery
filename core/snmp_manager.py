import logging, json
import asyncio

# pysnmp 7.x uses v3arch.asyncio for async SNMP operations (supports v1/v2c/v3)
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData, UsmUserData, SnmpEngine, ContextData,
    ObjectType, ObjectIdentity, 
    get_cmd, next_cmd, bulk_cmd, walk_cmd,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, usm3DESEDEPrivProtocol, 
    usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol
)
from pysnmp.hlapi.v3arch.asyncio.transport import UdpTransportTarget

from core.utils import ensure_directory_exists

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
            
        log_path = 'logs/snmp_errors.log'
        
        ensure_directory_exists(log_path)

        # Configure logging to ONLY write to file, not console
        logging.basicConfig(
            filename=log_path,  
            level=logging.INFO,  # Changed to INFO to capture more details
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            force=True  # Override any existing configuration
        )
        # Disable propagation to console
        logging.getLogger().handlers = [h for h in logging.getLogger().handlers if not isinstance(h, logging.StreamHandler) or h.stream.name != '<stderr>']

    def __validate_snmpv3_params(self):
        """
        Validate SNMPv3 parameters to ensure they are correct objects required by UsmUserData.
        """
        if not self.user or not self.auth_key or not self.priv_key or not self.auth_protocol or not self.priv_protocol:
            raise ValueError("User, auth_key, priv_key, auth_protocol, and priv_protocol are required for SNMPv3")
        
        # In pysnmp > 6, protocol objects might need verification or just passed through.
        # Assuming standard usage, we keep this basic validation or relax it if protocols are passed as strings/constants
        pass


    async def snmp_discovery(self, target, base_oid='1.3.6.1.2.1.1', use_next_cmd=True):
        """
        Perform SNMP discovery on a target device with timeout.
        Args:
            target (str): The IP address or hostname of the target device.
            base_oid (str, optional): The base OID to start the discovery from. Defaults to '1.3.6.1.2.1.1'.
            use_next_cmd (bool, optional): Whether to use the SNMP walk (True) or single get (False). Defaults to True.
        Returns:
            list: A list of tuples containing OID and value pairs discovered.
        Raises:
            ValueError: If required parameters for the specified SNMP version are missing or if an invalid SNMP version is specified.
            asyncio.TimeoutError: If the operation takes longer than the timeout
        """
        try:
            # Wrap the actual discovery with a timeout
            return await asyncio.wait_for(
                self._snmp_discovery_internal(target, base_oid, use_next_cmd),
                timeout=60.0  # 60 second timeout for slower devices
            )
        except asyncio.TimeoutError:
            logging.error(f'SNMP discovery timeout for {target} OID {base_oid}')
            return []  # Return empty list on timeout
    
    async def _snmp_discovery_internal(self, target, base_oid='1.3.6.1.2.1.1', use_next_cmd=True):
        """
        Perform SNMP discovery on a target device.
        Args:
            target (str): The IP address or hostname of the target device.
            base_oid (str, optional): The base OID to start the discovery from. Defaults to '1.3.6.1.2.1.1'.
            use_next_cmd (bool, optional): Whether to use the SNMP walk (True) or single get (False). Defaults to True.
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
    
        # Create transport target using async .create() method
        transport = await UdpTransportTarget.create((target, 161))
    
        if use_next_cmd:
            # walk_cmd returns an AsyncGenerator - use async for
            result_count = 0
            max_results = 500  # Reduced limit for faster operation
            async for errorIndication, errorStatus, errorIndex, varBinds in walk_cmd(
                SnmpEngine(),
                user_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
            ):
                result_count += 1
                if result_count > max_results:
                    logging.warning(f'Reached max results limit ({max_results}) for {base_oid}')
                    break
                    
                if errorIndication or errorStatus:
                    if errorIndication:
                        logging.error(f'Error Indication: {errorIndication}')
                    if errorStatus:
                        logging.error(f'Error Status: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
                    continue
                else:
                    for varBind in varBinds:
                        oid, value = varBind
                        # Clean numeric OID string
                        oid_str = str(oid)
                        
                        # Subtree Validation: Verify the returned OID actually belongs to the requested base_oid
                        # Standard SNMP walk (next_cmd) continues until the end of MIB view if not stopped using lexicographical check
                        if base_oid and not oid_str.startswith(base_oid):
                            # We have gone past the requested subtree
                            # Stop the iterator/loop. But since we are in async for loop from library, we break
                            # However, pysnmp's walk_cmd might arguably handle this if configured? 
                            # Usually simple walk implementations need this check manually.
                            return results 

                        results.append((oid_str, value.prettyPrint()))
        else:
           # get_cmd is a coroutine that returns a single tuple - await it directly
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                SnmpEngine(),
                user_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
            )
            if errorIndication or errorStatus:
                if errorIndication:
                    logging.error(f'Error Indication: {errorIndication}')
                if errorStatus:
                    logging.error(f'Error Status: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
            else:
                for varBind in varBinds:
                    oid, value = varBind
                    # For get_cmd usually we get what we asked for, but consistency helps
                    results.append((str(oid), value.prettyPrint()))
        
        return results

    async def validate_snmp_reachability(self, target):
        """
        Check if the target is reachable via SNMP.
        """
        try:
            # Using sysDescr as validation
            logging.info(f'Validating SNMP reachability for {target} (v{self.version})')
            sys_descr = await self.snmp_discovery(target, "1.3.6.1.2.1.1.1.0", use_next_cmd=False)
            if sys_descr:
                logging.info(f'SNMP validation successful for {target}')
                return True
            else:
                logging.error(f'SNMP validation failed for {target} (No data returned)')
                return False
        except Exception as e:
            logging.error(f'SNMP validation exception for {target}: {e}')
            logging.error(f"SNMP validation failed for {target}: {e}")
            return False

    def _decode_hex_string(self, value):
        """
        Detects if a string is hex-encoded (starts with 0x) and decodes it.
        Uses the centralized decode_hex_string function from utils.
        """
        from core.utils import decode_hex_string
        return decode_hex_string(value)

    async def get_system_info(self, target):
        """
        Retrieve basic system information (Name, Description, ObjectID, Uptime, Contact, Location).
        """
        sys_info = {}
        oids = {
            "description": "1.3.6.1.2.1.1.1.0",
            "object_id": "1.3.6.1.2.1.1.2.0",
            "uptime": "1.3.6.1.2.1.1.3.0",
            "contact": "1.3.6.1.2.1.1.4.0",
            "name": "1.3.6.1.2.1.1.5.0",
            "location": "1.3.6.1.2.1.1.6.0",
            "services": "1.3.6.1.2.1.1.7.0"
        }
        
        for key, oid in oids.items():
            result = await self.snmp_discovery(target, oid, use_next_cmd=False)
            if result:
                value = result[0][1]
                # Apply hex decoding specifically for description, or potentially others
                if key == "description":
                    value = self._decode_hex_string(value)
                sys_info[key] = value
            else:
                sys_info[key] = "Unknown"
        
        return sys_info

    async def get_entity_info(self, target):
        """
        Retrieves entity (chassis) information including serial number and model.
        Uses ENTITY-MIB (entPhysicalTable).
        
        OIDs:
        - entPhysicalDescr: 1.3.6.1.2.1.47.1.1.1.1.2 (Description)
        - entPhysicalClass: 1.3.6.1.2.1.47.1.1.1.1.5 (Class: 3=chassis)
        - entPhysicalName: 1.3.6.1.2.1.47.1.1.1.1.7 (Name)
        - entPhysicalSerialNum: 1.3.6.1.2.1.47.1.1.1.1.11 (Serial Number)
        - entPhysicalModelName: 1.3.6.1.2.1.47.1.1.1.1.13 (Model Name)
        """
        entity_info = {
            "serial_number": "Unknown",
            "model": "Unknown",
            "chassis_description": ""
        }
        
        try:
            # Get physical class to find the chassis entry (class=3)
            phys_class = await self.snmp_discovery(target, "1.3.6.1.2.1.47.1.1.1.1.5", use_next_cmd=True)
            phys_serial = await self.snmp_discovery(target, "1.3.6.1.2.1.47.1.1.1.1.11", use_next_cmd=True)
            phys_model = await self.snmp_discovery(target, "1.3.6.1.2.1.47.1.1.1.1.13", use_next_cmd=True)
            phys_descr = await self.snmp_discovery(target, "1.3.6.1.2.1.47.1.1.1.1.2", use_next_cmd=True)
            
            # Build lookup dictionaries by index
            def build_dict(data):
                result = {}
                for oid, value in data:
                    idx = oid.split('.')[-1]
                    result[idx] = value
                return result
            
            class_dict = build_dict(phys_class)
            serial_dict = build_dict(phys_serial)
            model_dict = build_dict(phys_model)
            descr_dict = build_dict(phys_descr)
            
            # Find chassis entries (class=3) or stack entries (class=5)
            # Priority: chassis (3) > stack (5) > module (9)
            chassis_idx = None
            for idx, cls in class_dict.items():
                if cls == '3':  # Chassis
                    chassis_idx = idx
                    break
                elif cls == '5' and not chassis_idx:  # Container/Stack
                    chassis_idx = idx
                elif cls == '9' and not chassis_idx:  # Module
                    chassis_idx = idx
            
            # If no chassis found, try the first entry with a serial number
            if not chassis_idx:
                for idx, serial in serial_dict.items():
                    if serial and serial != "" and serial != "Unknown":
                        chassis_idx = idx
                        break
            
            if chassis_idx:
                serial = serial_dict.get(chassis_idx, "")
                model = model_dict.get(chassis_idx, "")
                descr = descr_dict.get(chassis_idx, "")
                
                # Decode hex strings
                from core.utils import decode_hex_string
                entity_info["serial_number"] = decode_hex_string(serial) if serial else "Unknown"
                entity_info["model"] = decode_hex_string(model) if model else "Unknown"
                entity_info["chassis_description"] = decode_hex_string(descr) if descr else ""
            
            # If model is still unknown, try to find any non-empty model
            if entity_info["model"] == "Unknown" or not entity_info["model"]:
                for idx, model in model_dict.items():
                    if model and model != "" and not model.startswith("0x"):
                        entity_info["model"] = model
                        break
                    elif model and model.startswith("0x"):
                        from core.utils import decode_hex_string
                        decoded = decode_hex_string(model)
                        if decoded and decoded != model:
                            entity_info["model"] = decoded
                            break
                            
        except Exception as e:
            logging.error(f"Error getting entity info for {target}: {e}")
        
        return entity_info

    async def get_snmp_neighbors(self, ip):
        """
        Retrieves SNMP neighbors for a given IP address using LLDP and CDP protocols.

        Args:
            ip (str): The IP address of the device to query for neighbors.

        Returns:
            list: A list of neighbors discovered via SNMP using LLDP and CDP protocols.
        """
        neighbors = []

        async def get_lldp_neighbors():
            lldp_oid = "1.0.8802.1.1.2.1.4"
            return await self.snmp_discovery(ip, lldp_oid)

        async def get_cdp_neighbors():
            cdp_oid = ".1.3.6.1.4.1.9.9.23.1.2.1"
            return await self.snmp_discovery(ip, cdp_oid)

        neighbors.extend(await get_lldp_neighbors())
        neighbors.extend(await get_cdp_neighbors())

        return neighbors


    async def get_local_ports(self, target):
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

        transport = await UdpTransportTarget.create((target, 161))

        async for errorIndication, errorStatus, errorIndex, varBinds in walk_cmd(
            SnmpEngine(),
            user_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(if_descr_oid)),
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

    async def get_full_interface_details(self, target):
        """
        Retrieves detailed interface information including Name, Mac, Status, Type.
        Uses ifXTable (ifName) for better interface names on modern devices.
        Also retrieves ifType to distinguish physical adapters from logical interfaces.
        """
        interfaces = []
        # ifTable/ifXTable columns
        # ifIndex: .1.3.6.1.2.1.2.2.1.1
        # ifDescr: .1.3.6.1.2.1.2.2.1.2 (basic name)
        # ifName: .1.3.6.1.2.1.31.1.1.1.1 (better name from ifXTable)
        # ifType: .1.3.6.1.2.1.2.2.1.3 (interface type - physical vs logical)
        # ifPhysAddress: .1.3.6.1.2.1.2.2.1.6
        # ifAdminStatus: .1.3.6.1.2.1.2.2.1.7
        # ifOperStatus: .1.3.6.1.2.1.2.2.1.8
        # ifAlias: .1.3.6.1.2.1.31.1.1.1.18 (interface description/alias)
        
        async def get_column(oid):
             logging.info(f'Walking SNMP OID: {oid} for {target}')
             res = await self.snmp_discovery(target, oid, use_next_cmd=True)
             logging.info(f'Retrieved {len(res)} results for OID {oid}')
             return {r[0].split('.')[-1]: r[1] for r in res}

        # Try ifName first (from ifXTable) - gives better names like "GigabitEthernet1/0/1"
        if_names = await get_column("1.3.6.1.2.1.31.1.1.1.1")
        
        # Fallback to ifDescr if ifName is not available
        if_descr = await get_column("1.3.6.1.2.1.2.2.1.2")
        
        # Get ifType to distinguish physical adapters from logical interfaces
        if_types = await get_column("1.3.6.1.2.1.2.2.1.3")
        
        # Merge: prefer ifName, fallback to ifDescr
        names = {}
        all_indices = set(if_names.keys()) | set(if_descr.keys())
        for idx in all_indices:
            # Prefer ifName if available and not empty/hex
            if_name_val = if_names.get(idx, "")
            if_descr_val = if_descr.get(idx, "")
            
            # Use ifName if it looks valid (not hex, not empty)
            if if_name_val and not if_name_val.startswith("0x"):
                names[idx] = if_name_val
            elif if_descr_val and not if_descr_val.startswith("0x"):
                names[idx] = if_descr_val
            else:
                # Both are hex or empty, try to decode
                from core.utils import decode_hex_string
                decoded_name = decode_hex_string(if_name_val) if if_name_val else ""
                decoded_descr = decode_hex_string(if_descr_val) if if_descr_val else ""
                names[idx] = decoded_name or decoded_descr or f"Interface_{idx}"
        
        macs = await get_column("1.3.6.1.2.1.2.2.1.6")
        oper_status = await get_column("1.3.6.1.2.1.2.2.1.8")
        
        # Get interface aliases/descriptions
        if_alias = await get_column("1.3.6.1.2.1.31.1.1.1.18")
        
        # IP Addresses are in ipAddrTable usually mapped to ifIndex
        # ipAdEntAddr .1.3.6.1.2.1.4.20.1.1 (Use as key)
        # ipAdEntIfIndex .1.3.6.1.2.1.4.20.1.2
        # ipAdEntNetMask .1.3.6.1.2.1.4.20.1.3
        
        ip_mapping = {}
        ip_indices = await self.snmp_discovery(target, "1.3.6.1.2.1.4.20.1.2", use_next_cmd=True)
        ip_masks = await self.snmp_discovery(target, "1.3.6.1.2.1.4.20.1.3", use_next_cmd=True)
        
        # Create a mapping of ifIndex -> list of {ip, mask}
        if_ip_map = {}
        if ip_indices:
             for oid, if_idx in ip_indices:
                 # The IP address is encoded in the last 4 parts of the OID
                 # Example OID: 1.3.6.1.2.1.4.20.1.2.192.168.1.1
                 oid_parts = oid.split('.')
                 if len(oid_parts) >= 4:
                     ip_addr = '.'.join(oid_parts[-4:])
                 else:
                     ip_addr = oid
                 
                 # Find corresponding mask
                 mask = "Unknown"
                 for m_oid, m_val in ip_masks:
                     m_oid_parts = m_oid.split('.')
                     if len(m_oid_parts) >= 4:
                         m_ip = '.'.join(m_oid_parts[-4:])
                         if m_ip == ip_addr:
                             mask = m_val
                             break
                 
                 if if_idx not in if_ip_map:
                     if_ip_map[if_idx] = []
                 if_ip_map[if_idx].append({"ip": ip_addr, "mask": mask})

        for idx, name in names.items():
            mac_hex = macs.get(idx, "")
            # Convert hex string (e.g. 0x...) to standard MAC format
            if mac_hex.startswith("0x"):
                 mac_clean = mac_hex.replace("0x", "")
                 # Ensure even length
                 if len(mac_clean) % 2 == 1:
                     mac_clean = '0' + mac_clean
                 mac_formatted = ":".join([mac_clean[i:i+2] for i in range(0, len(mac_clean), 2)])
            else:
                 mac_formatted = mac_hex

            status_map = {'1': 'up', '2': 'down', '3': 'testing'}
            status = status_map.get(oper_status.get(idx, '0'), 'unknown')
            
            # Get alias/description
            alias = if_alias.get(idx, "")
            if alias and alias.startswith("0x"):
                from core.utils import decode_hex_string
                alias = decode_hex_string(alias)

            if_data = {
                "index": idx,
                "name": name,
                "description": alias if alias else "",
                "mac": mac_formatted,
                "status": status,
                "ips": if_ip_map.get(idx, []),
                "if_type": if_types.get(idx, "0")  # ifType for physical vs logical detection
            }
            interfaces.append(if_data)
            
        return interfaces
    

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

    async def get_remote_interface(self, neighbor_ip, source_ip, local_port_oid):
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
        remote_interface_result = await self.snmp_discovery(neighbor_ip, lldp_remote_oid, False)
        
        if self.__is_protocol_not_enabled(remote_interface_result):
            print("LLDP is not enabled on the interfaces of the target device!")
            return "LLDP is not enabled on the interface."
        
        # Fallback to CDP if LLDP fails
        if not remote_interface_result:
            remote_interface_result = await self.snmp_discovery(neighbor_ip, cdp_remote_oid, False)
        
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