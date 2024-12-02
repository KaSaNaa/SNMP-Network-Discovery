import ipaddress
import os
import socket
import concurrent.futures

def get_dns_hostname(ip):
    """
    Get the DNS hostname for a given IP address.

    This function attempts to resolve the given IP address to its corresponding
    DNS hostname. If the hostname is successfully resolved, the function returns
    the short hostname (i.e., the first part of the fully qualified domain name).
    If the hostname cannot be resolved, the function returns the original IP address.

    Parameters
    ----------
    ip : str
        The IP address to resolve.

    Returns
    -------
    str
        The short hostname if resolution is successful, otherwise the original IP address.

    Examples
    --------
    >>> get_dns_hostname("8.8.8.8")
    'dns.google'

    >>> get_dns_hostname("192.168.1.1")
    'router'

    >>> get_dns_hostname("256.256.256.256")
    '256.256.256.256'
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        short_hostname = hostname.split(".")[0]
        if short_hostname:
            return short_hostname
        else:
            return ip
    except socket.herror:
        return ip

def ping_ip(ip_str):
    """
    Ping an IP address to check its availability.

    This function takes an IP address as a string, validates it, and then attempts to ping it.
    If the IP address is valid and the ping is successful, the function returns the IP address.
    Otherwise, it returns None.

    Parameters:
    ip_str (str): The IP address to be pinged.

    Returns:
    str: The IP address if the ping is successful.
    None: If the IP address is invalid or the ping fails.

    Raises:
    ValueError: If the provided IP address is not valid.

    Example:
    >>> ping_ip("192.168.1.1")
    '192.168.1.1'
    >>> ping_ip("256.256.256.256")
    Invalid IP address '256.256.256.256': '256.256.256.256' does not appear to be an IPv4 or IPv6 address
    None
    """
    try:
        ipaddress.ip_address(ip_str)
        response = os.system(f"ping -c 1 -W 1 {ip_str} > /dev/null 2>&1")
        if response == 0:
            return ip_str
    except ValueError as e:
        print(f"Invalid IP address '{ip_str}': {e}")
    return None

def get_ips_from_subnets(subnets):
    """
    Generate a list of all possible IP addresses from a list of subnets.

    This function takes a list of subnet strings, converts each subnet to an 
    ipaddress.ip_network object, and then extracts all possible host IP addresses 
    from each subnet. If a subnet is invalid, it prints an error message and 
    continues processing the remaining subnets.

    Parameters
    ----------
    subnets : list of str
        A list of subnet strings in CIDR notation (e.g., '192.168.1.0/24').

    Returns
    -------
    list of str
        A list of IP addresses as strings.

    Raises
    ------
    ValueError
        If a subnet string is not a valid subnet, an error message is printed.

    Examples
    --------
    >>> get_ips_from_subnets(['192.168.1.0/30'])
    ['192.168.1.1', '192.168.1.2']

    >>> get_ips_from_subnets(['192.168.1.0/31'])
    []

    >>> get_ips_from_subnets(['192.168.1.0/24', '10.0.0.0/30'])
    ['192.168.1.1', '192.168.1.2', ..., '192.168.1.254', '10.0.0.1', '10.0.0.2']

    >>> get_ips_from_subnets(['invalid_subnet'])
    Invalid subnet invalid_subnet: 'invalid_subnet' does not appear to be an IPv4 or IPv6 network
    []
    """
    all_ips = []
    for subnet in subnets:
        try:
            net = ipaddress.ip_network(subnet)
            for ip in net.hosts():
                all_ips.append(str(ip))
        except ValueError as e:
            print(f"Invalid subnet {subnet}: {e}")
    return all_ips

def scan_subnet(ip_list):
    """
    Scans a list of IP addresses to determine which ones are active.

    This function uses a ThreadPoolExecutor to concurrently ping a list of IP addresses.
    It returns a list of active IP addresses that responded to the ping.

    Parameters
    ----------
    ip_list : list of str
        A list of IP addresses to be scanned.

    Returns
    -------
    list of str
        A list of active IP addresses that responded to the ping.

    Examples
    --------
    >>> ip_list = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
    >>> active_ips = scan_subnet(ip_list)
    >>> print(active_ips)
    ['192.168.1.1', '192.168.1.3']
    """
    active_ips = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(ping_ip, ip): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                active_ips.append(result)
    return active_ips