from scapy.all import ARP, Ether, srp

def send_arp_request(target_ip, iface):
    """Send ARP request and wait for a response using Scapy."""

    # Create an ARP request packet
    arp_request = ARP(pdst=target_ip, psrc="224.0.0.1")

    # Create an Ethernet frame to encapsulate the ARP request
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the Ethernet frame and ARP request
    arp_request_packet = ether_frame / arp_request

    # Send the ARP request and capture responses
    # scapy.srp returns a tuple of two lists
    answered, unanswered = srp(arp_request_packet, timeout=2, iface=iface, verbose=False)

    # Iterate through the answered list. The answered list itself is a tuple.
    for sent, received in answered:
        print(f"Received ARP response from {received.psrc} ({received.hwsrc})")
        if (received.psrc == target_ip):
            return received

    #If we did not find a recieved ARP message from the target IP the test failed
    return None

def test_malformed_arp_handling():
    interface = "veth0"         # Adjust this to your virtual interface 
    target_ip = "192.168.1.2"   # The IP you expect to reply to ARP requests

    # Step 1: Send ARP Request and capture response
    print(f"Sending ARP request to {target_ip}...")
    response = send_arp_request(target_ip, interface)

    # Step 2: Validate Test Results
    # Since the Source IP address is a multicast DAI should drop the packets and no responses should be received
    if response is not None:
        print(f"ARP response received from: {response.psrc}")
        assert False, "ARP Response recieved"
    else:
        print(f"No ARP response received from target: {target_ip}.")
        assert True, "ARP response not received"

if __name__ == "__main__":
    # Running the test
    try:
        test_malformed_arp_handling()
        print("Test passed!")
        assert(True)
    except AssertionError as e:
        print(f"Test failed!")
        assert(False)
