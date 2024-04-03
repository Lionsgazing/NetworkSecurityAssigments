import socket
from IPV4 import IPV4
from ICMP import ICMP

from Crypto.Cipher import ChaCha20_Poly1305
from payload import SecurePayload

from secret_key import secret_key

def main():
    # Calculate the max payload size from the headers
    MAX_PAYLOAD_SIZE = 2**16-1 - IPV4.HEADER_SIZE - ICMP.HEADER_SIZE

    # Setup socket using IPV4 and raw socket with expected ICMP header.
    host = "127.0.0.1"
    port = 50007

    sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sockfd.bind((host, port))

    payload: bytes = b'Hello im a message and im very sensitive so im going to travel through this covert ICMP channel while being encrypted.'


    secure_payload = SecurePayload(cipher_type="ChaCha20_Poly1305", key=secret_key)

    icmp = ICMP(47, 0)
    icmp_msg = icmp.create_message(secure_payload.encrypt(payload, True))


    #for icmp_msg in icmp_msg_collection:
    sockfd.sendto(icmp_msg, (host, port))




if (__name__ == "__main__"):
    main()