from scapy.all import ARP, Ether, srp
import netifaces
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import subprocess

# Define color constants globally
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
END = '\033[0m'

def print_ascii_art():
    """ Prints the ASCII art for 'Owlspec' and 'Network Scanner' using figlet """
    try:
        owlspec_art = subprocess.check_output(['figlet', '-f', 'big', 'Owlspec'], universal_newlines=True)
        network_scanner_art = subprocess.check_output(['figlet', '-f', 'mini', 'Network Scanner'], universal_newlines=True)
    except subprocess.CalledProcessError as e:
        print("Failed to generate ASCII art. Is figlet installed?")
        return

    print(YELLOW + owlspec_art + END)
    print(BLUE + network_scanner_art + END)

def get_gateway_ip():
    """ Get the default gateway IP address """
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]

def ping_host(ip):
    """ Uses the system's ping command to ping the specified IP address """
    try:
        subprocess.check_output(['ping', '-c', '1', '-W', '1', ip], stderr=subprocess.STDOUT, universal_newlines=True)
        return True
    except subprocess.CalledProcessError:
        return False

def scan(ip):
    """ Scan the network """
    mac_lookup = MacLookup()
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        status = "up" if ping_host(received.psrc) else "down"
        try:
            vendor = mac_lookup.lookup(received.hwsrc)
        except VendorNotFoundError:
            vendor = 'Unknown'

        clients.append({'ip': received.psrc, 'mac': received.hwsrc, 'vendor': vendor, 'status': status})

    # Sort the list of clients by vendor name in alphabetical order
    clients.sort(key=lambda x: x['vendor'])
    return clients

def print_device_info(clients):
    """ Prints the device information in a well-formatted table with colored output based on status. """
    header = f"{'IP Address':<18} {'MAC Address':<20} {'Vendor':<30} {'Status'}"
    print(header)
    print('-' * len(header))

    for client in clients:
        status_colored = f"{GREEN if client['status'] == 'up' else RED}{client['status']}{END}"
        print(f"{client['ip']:<18} {client['mac']:<20} {client['vendor']:<30} {status_colored}")

if __name__ == "__main__":
    print_ascii_art()
    gateway_ip = get_gateway_ip()
    target_ip = gateway_ip + "/24"  # Assuming a subnet mask of 255.255.255.0
    clients = scan(target_ip)
    print_device_info(clients)