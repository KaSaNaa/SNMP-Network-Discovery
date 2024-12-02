import socket


def get_windows_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname, None
    except socket.herror as e:
        return None, f"Error: {e}"


if __name__ == "__main__":
    # Replace with your target IP
    target_ip = "127.0.0.1"

    hostname, error = get_windows_hostname(target_ip)

    if hostname:
        print(f"Hostname: {hostname}")
    else:
        print(f"Error: {error}")
