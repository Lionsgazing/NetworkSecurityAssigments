import socket
from IPV4 import IPV4
from ICMP import ICMP

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import random

from SecurePayload import SecurePayload

from secret_key import secret_key1

def main():
    # Debug info flag
    SHOW_DEBUG_INFO = True

    # Calculate the max payload size from the headers
    MAX_PAYLOAD_SIZE = 2**16-1 - IPV4.HEADER_SIZE - ICMP.HEADER_SIZE

    # Setup socket
    host = ""
    port = 0 # Does not matter

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((host, port))

    # Setup secure payload class with the correct cipher type and known secret key.
    secure_payload = SecurePayload(cipher_type="ChaCha20_Poly1305", key=secret_key1)

    print("############################")
    print("ICMP Covert Messaging Server")
    print("############################")
    print("Messages recieved:")

    isRunning = True
    msg_counter = 0

    while(isRunning):
        # Recv messages
        msg, addr = sock.recvfrom(MAX_PAYLOAD_SIZE)

        # Isolate IPV4 packet
        ipv4 = IPV4.from_message(msg)
        
        # Isolate ICMP packet from IPV4 packet
        icmp = ICMP.from_message(ipv4.payload)

        if (SHOW_DEBUG_INFO):
            # Debug info
            msg_header_str = f'{msg_counter}: Message from {addr[0]}:'
            msg_seperator_str = f'#' * len(msg_header_str)
            print(msg_seperator_str) # Only show ip since ICMP does not care about the port used.
            print(msg_header_str)
            print(msg_seperator_str)
            print(ipv4)
            print(icmp)

        # Get the ICMP payload and decrypt it with our secure payload class.
        plaintext = secure_payload.decrypt(icmp.payload, SHOW_DEBUG_INFO)

        if (SHOW_DEBUG_INFO):
            # Debug info
            print("\nMessage Info")
            print(f'- Ciphertext: {secure_payload.disect_payload(icmp.payload)[-1].hex()}')
            print(f'- Plaintext: {plaintext.decode(encoding='utf-8')}\n')
        else:
            # Normal operation
            print(f'{msg_counter} - {addr[0]}: {plaintext.decode(encoding="utf-8")}')

        # Count messages
        msg_counter += 1

if (__name__ == "__main__"):
    main()