import sys
import socket

from IPV4 import IPV4
from ICMP import ICMP
from SecurePayload import SecurePayload
from secret_key import secret_key1

def error(msg: str):
    print("Error: " + msg)
    print_usage()
    exit(1)

def print_usage():
    print("USAGE:")
    print("icmp_client.py [ipb4 address]")

def main():
    # Debug info flag
    SHOW_DEBUG_INFO = True

    # Calculate the max payload size from the headers
    MAX_PAYLOAD_SIZE = 2**16-1 - IPV4.HEADER_SIZE - ICMP.HEADER_SIZE

    # Check for passed arguments
    if (len(sys.argv) <= 1):
        error("No ipv4 address argument passed...")
    elif len(sys.argv) > 2:
        error("Too many arguments passed.")
    target_addr = sys.argv[1]
    
    # Setup socket using IPV4 and raw socket with expected ICMP header.
    host = target_addr
    port = 0 # Does not matter!

    sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Try to bind. Might fail if passed ipv4 address is not valid.
    try:
        sockfd.bind((host, port))
    except:
        error("Couldn't bind socket to given IPV4 target address. IPV4 address might not be valid!")


    print("############################")
    print("ICMP Covert Messaging Client")
    print(f'- IP Target: {host}')
    print("############################")
    print("Messaging terminal:")

    while (True):
        # Wait for user input
        payload_str = input("> ")

        # Convert to a sendable payload
        payload = bytes(payload_str, encoding="utf-8")
        secure_payload = SecurePayload(cipher_type="ChaCha20_Poly1305", key=secret_key1)

        # Create ICMP header and attach encrypted message
        icmp = ICMP(47, 0)
        icmp_msg = icmp.create_message(secure_payload.encrypt(payload, SHOW_DEBUG_INFO))

        # Send message
        sockfd.sendto(icmp_msg, (host, port))

if (__name__ == "__main__"):
    main()