import networkx as nx
import matplotlib.pyplot as plt
import json
from .network_utils import NetworkUtils
from .snmp_manager import SNMPManager
from .database_manager import DatabaseManager
from .screen_utils import ScreenUtils

class GraphManager:
    def __init__(self, version=None, community=None, user=None, auth_key=None, priv_key=None, auth_protocol=None, priv_protocol=None):
        self.snmp_manager = SNMPManager(version, community, user, auth_key, priv_key, auth_protocol, priv_protocol)
        self.db_manager = DatabaseManager()

    def build_topology(self, json_file_path):
        G = nx.Graph()
        # NetworkUtils.save_local_ip_to_env()

        with open(json_file_path, 'r') as json_file:
            discovered_devices = json.load(json_file)

        for device in discovered_devices:
            for ip, details in device.items():
                device_name = details["hostname"]
                G.add_node(device_name, label=device_name)
                print(f"Adding device: {ip} ({device_name})")

                for neighbor_ip, neighbor_details in details["neighbors"].items():
                    neighbor_name = neighbor_details["details"]["hostname"]
                    local_interface = neighbor_details["local_interface"]
                    remote_interface = neighbor_details["remote_interface"]

                    G.add_node(neighbor_name, label=neighbor_name)
                    G.add_edge(device_name, neighbor_name, label=f"{local_interface} -> {remote_interface}")
                    print(f"Adding edge: {device_name} ({local_interface}) -> {neighbor_name} ({remote_interface})")

        return G

    def draw_topology(self, graph):
        screen_width_px, screen_height_px = ScreenUtils.get_screen_size()
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