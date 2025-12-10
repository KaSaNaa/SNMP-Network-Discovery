import ipaddress
import subprocess
import platform
import socket
import os
import concurrent.futures

class NetworkUtils:
    @staticmethod
    def get_local_ip():
        """
        Get the local IP address of the machine.

        This function creates a UDP socket connection to a public DNS server (8.8.8.8)
        to determine the local IP address of the machine. The socket is closed after
        retrieving the IP address.

        Returns:
            str: The local IP address of the machine, or None if an error occurs.

        Raises:
            Exception: If there is an error in creating the socket or retrieving the IP address.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return None

    @staticmethod
    def save_local_ip_to_env():
        """
        Retrieves the local IP address using NetworkUtils.get_local_ip() and saves it to a .env file as the value of DB_HOST.
        If the .env file already exists, it updates the DB_HOST entry with the local IP address. If the DB_HOST entry does not exist, it adds it.
        If the .env file does not exist, it creates the file and adds the DB_HOST entry with the local IP address.
        If the local IP address cannot be retrieved, it prints an error message.
        """
        local_ip = NetworkUtils.get_local_ip()
        if local_ip:
            env_file_path = '.env'
            if os.path.exists(env_file_path):
                with open(env_file_path, 'r') as env_file:
                    lines = env_file.readlines()
                
                with open(env_file_path, 'w') as env_file:
                    db_host_found = False
                    for line in lines:
                        if line.startswith('DB_HOST='):
                            env_file.write(f'DB_HOST={local_ip}\n')
                            db_host_found = True
                        else:
                            env_file.write(line)
                    
                    if not db_host_found:
                        env_file.write(f'DB_HOST={local_ip}\n')
            else:
                with open(env_file_path, 'w') as env_file:
                    env_file.write(f'DB_HOST={local_ip}\n')
        else:
            print("Failed to retrieve local IP address.")


    @staticmethod
    def get_dns_hostname(ip):
        """
        Resolves the DNS hostname for a given IP address.

        Args:
            ip (str): The IP address to resolve.

        Returns:
            str: The short hostname if resolution is successful, otherwise the original IP address.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            short_hostname = hostname.split(".")[0]
            return short_hostname if short_hostname else ip
        except socket.herror:
            return ip

    @staticmethod
    def ping_ip(ip_str):
        """
        Ping an IP address to check its availability.

        Args:
            ip_str (str): The IP address to ping.

        Returns:
            str: The IP address if the ping is successful.
            None: If the ping fails or the IP address is invalid.

        Raises:
            ValueError: If the provided IP address is not valid.

        Example:
            >>> ping_ip("192.168.1.1")
            '192.168.1.1'
            
            >>> ping_ip("256.256.256.256")
            Invalid IP address '256.256.256.256': ...
            None
        """
        try:
            ipaddress.ip_address(ip_str)
            system = platform.system()
            command = ["ping", "-n", "1", "-w", "1000", ip_str] if system == "Windows" else ["ping", "-c", "1", "-W", "1", ip_str]
            response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return ip_str if response.returncode == 0 else None
        except ValueError as e:
            print(f"Invalid IP address '{ip_str}': {e}")
            return None

    @staticmethod
    def get_ips_from_subnets(subnets):
        """
        Generate a list of all possible IP addresses from a list of subnets.

        Args:
            subnets (list of str): A list of subnet strings in CIDR notation.

        Returns:
            list of str: A list of IP addresses as strings.

        Raises:
            ValueError: If any of the subnet strings are invalid.
        """
        all_ips = []
        for subnet in subnets:
            try:
                net = ipaddress.ip_network(subnet)
                all_ips.extend(str(ip) for ip in net.hosts())
            except ValueError as e:
                print(f"Invalid subnet {subnet}: {e}")
        return all_ips

    @staticmethod
    def scan_subnet(ip_list):
        """
        Scans a list of IP addresses to determine which ones are active.

        Args:
            ip_list (list): A list of IP addresses to scan.

        Returns:
            list: A list of active IP addresses.
        """
        active_ips = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(NetworkUtils.ping_ip, ip): ip for ip in ip_list}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    active_ips.append(result)
        return active_ips