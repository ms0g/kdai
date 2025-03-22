from scapy.all import *

def update_DHCP(interface,servers_ip_address,clients_new_ip_address,clients_mac_address):

    # Define the client MAC address
    client_mac = clients_mac_address  # Replace with actual client MAC

    # Construct DHCP ACK packet
    dhcp_ack = (
        Ether(src="00:11:22:33:44:55", dst=client_mac) /  # Server MAC to Client MAC
        IP(src=servers_ip_address, dst="255.255.255.255") /  # Server IP
        UDP(sport=67, dport=68) /  # DHCP Server-to-Client ports
        BOOTP(
            op=2,  # Reply (2 = BOOTREPLY)
            yiaddr=clients_new_ip_address,  # Assigned IP
            siaddr=servers_ip_address,  # DHCP Server IP
            chaddr=bytes.fromhex(client_mac.replace(":", ""))  # Client MAC in bytes
        ) /
        DHCP(options=[
            ("message-type", "ack"),
            ("server_id", servers_ip_address),  # DHCP Server IP
            ("subnet_mask", "255.255.255.0"),
            ("router", servers_ip_address),  # Default Gateway
            ("lease_time", 3600),  # Lease time in seconds
            "end"
        ])
    )

    # Send the packet
    sendp(dhcp_ack, iface="veth0", verbose=True)  # Replace "eth0" with your actual network interface

def dhcp_handling():
    interface = "veth0"
    servers_ip_address="192.168.1.100"
    clients_new_ip_address="192.168.1.1"
    clients_mac_address="e2:c8:14:a6:4f:ed"
    update_DHCP(interface,servers_ip_address,clients_new_ip_address,clients_mac_address)

    interface = "veth3"
    servers_ip_address="192.168.1.100"
    clients_new_ip_address="192.168.1.2"
    clients_mac_address="3a:18:70:ca:91:b2"
    update_DHCP(interface,servers_ip_address,clients_new_ip_address,clients_mac_address)


if __name__ == "__main__":
    dhcp_handling()
  