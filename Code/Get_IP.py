import netifaces

def get_ip():
    """
    Get the IP address of the default network interface.

    Returns:
        -ip: The IP address of the default network interface
    """
    ip = netifaces.ifaddresses(netifaces.gateways()['default'][netifaces.AF_INET][1])
    return ip[2][0]['broadcast'].replace('255', '1')

print(get_ip())