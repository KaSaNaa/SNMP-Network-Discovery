import networkx as nx
import matplotlib.pyplot as plt
from utils.network import get_dns_hostname
from trash.snmp import get_snmp_neighbors, get_local_ports
from utils.database import get_host_name_by_address
from utils.screen import get_screen_size

def build_topology(active_ips, user, auth_key, priv_key, auth_protocol, priv_protocol):
    """
    Builds a network topology graph using SNMP data.

    This function creates a network topology graph by discovering devices and their connections
    using SNMP (Simple Network Management Protocol). It adds nodes for each device and edges
    representing the connections between them.

    Parameters:
    active_ips (list): A list of IP addresses of active devices to be included in the topology.
    user (str): The SNMPv3 username.
    auth_key (str): The SNMPv3 authentication key.
    priv_key (str): The SNMPv3 privacy key.
    auth_protocol (str): The SNMPv3 authentication protocol (e.g., 'MD5', 'SHA').
    priv_protocol (str): The SNMPv3 privacy protocol (e.g., 'DES', 'AES').

    Returns:
    networkx.Graph: A graph object representing the network topology.

    Example:
    >>> active_ips = ['192.168.1.1', '192.168.1.2']
    >>> user = 'snmpuser'
    >>> auth_key = 'authkey'
    >>> priv_key = 'privkey'
    >>> auth_protocol = 'SHA'
    >>> priv_protocol = 'AES'
    >>> G = build_topology(active_ips, user, auth_key, priv_key, auth_protocol, priv_protocol)
    >>> print(G.nodes)
    ['Device1', 'Device2']
    >>> print(G.edges)
    [('Device1', 'Device2')]

    Note:
    - This function requires the `networkx` library.
    - The `get_dns_hostname`, `get_local_ports`, `get_host_name_by_address`, and `get_snmp_neighbors`
      functions must be defined elsewhere in your codebase.
    """
    G = nx.Graph()
    for ip in active_ips:
        dns_host_name = get_dns_hostname(ip)
        print("DNS HOST NAME: " + dns_host_name)
        remote_port_array = []
        local_port_array = []
        remote_device_array = []
        local_ports = get_local_ports(ip, user, auth_key, priv_key, auth_protocol, priv_protocol)
        device_name = get_host_name_by_address(ip)
        G.add_node(device_name, label=device_name)
        print(ip + " " + device_name)
        neighbors = get_snmp_neighbors(ip, user, auth_key, priv_key, auth_protocol, priv_protocol)
        for oid, value in neighbors:
            local_device = device_name
            if oid:
                if "0.8802.1.1.2.1.4.1.1.7" in oid:
                    remote_port_array.append(value)
                if "0.8802.1.1.2.1.4.1.1.2" in oid:
                    local_port = local_ports.get(value, "N/A")
                    local_port_array.append(local_port)
                if "0.8802.1.1.2.1.4.1.1.9" in oid:
                    r1 = value.split(".")[0]
                    remote_device_array.append(r1)
        i = 0
        for d in remote_device_array:
            G.add_node(d, label=d)
            G.add_edge(device_name, d, label=remote_port_array[i])
            i = i + 1
    return G

def draw_topology(graph):
    """
    Draws the network topology of the given graph and saves it as an image file.

    This function uses the NetworkX library to create a visual representation of the network topology
    and saves the resulting image as "network_topology.png". The layout of the nodes is determined
    using the spring layout algorithm.

    Parameters
    ----------
    graph : networkx.Graph
        The graph representing the network topology. Nodes and edges should have 'label' attributes
        for proper labeling in the visualization.

    Examples
    --------
    >>> import networkx as nx
    >>> from network_discovery.utils.graph import draw_topology
    >>> G = nx.Graph()
    >>> G.add_node(1, label='Router')
    >>> G.add_node(2, label='Switch')
    >>> G.add_edge(1, 2, label='Ethernet')
    >>> draw_topology(G)
    This will create a file named "network_topology.png" with the visual representation of the graph.

    Notes
    -----
    - The function assumes that the screen size can be obtained using the `get_screen_size` function.
    - The image is saved with a maximum size of 16384x16384 pixels to ensure compatibility with most
      image viewers.
    - The layout of the nodes is fixed using a seed value of 42 for reproducibility.
    """
    screen_width_px, screen_height_px = get_screen_size()
    dpi = 100
    max_size_px = 16384
    scale_factor = min(max_size_px / screen_width_px, max_size_px / screen_height_px, 1)
    screen_width_px *= scale_factor
    screen_height_px *= scale_factor
    screen_width_inch = screen_width_px / dpi
    screen_height_inch = screen_height_px / dpi
    pos = nx.spring_layout(graph, seed=42)
    plt.figure(figsize=(18, 10))
    nx.draw_networkx_nodes(graph, pos, node_size=500, node_color="lightblue", edgecolors="black")
    nx.draw_networkx_edges(graph, pos, width=1, alpha=0.7, edge_color="black")
    nx.draw_networkx_labels(graph, pos, labels=nx.get_node_attributes(graph, "label"), font_size=10, font_family="sans-serif")
    edge_labels = nx.get_edge_attributes(graph, "label")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels, font_color="red", font_size=8)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig("network_topology.png")