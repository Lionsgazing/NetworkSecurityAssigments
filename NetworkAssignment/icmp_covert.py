import socket

def create_ICMP_message(type: int, code: int, payload: str):
    MIN_ICMP_PAYLOAD_SIZE = 4
    MAX_ICMP_PAYLOAD_SIZE = 576

    icmp_type = int.to_bytes(type, 1, 'big') # 1 Byte
    icmp_code = int.to_bytes(code, 1, 'big') # 1 Byte
    icmp_checksum = int.to_bytes(0, 2, 'big') # 2 Bytes
 
    # Convert payload to bytes
    icmp_total_payload = bytes(payload, 'utf-8') # X bytes, max 576.

    # Check if payload is below minimum size and extend it if needed be
    if (len(icmp_total_payload) < MIN_ICMP_PAYLOAD_SIZE):
        icmp_total_payload = icmp_total_payload + b'\x00' * (MIN_ICMP_PAYLOAD_SIZE - len(icmp_total_payload))

    # Figure out if we need to generate more messages to fit the payload in a transmission.
    msgs_to_generate = len(payload) // MAX_ICMP_PAYLOAD_SIZE + 1 # Integer division

    # Create messages needed
    icmp_msg_collection: list[bytes] = []
    for i in range(msgs_to_generate):
        # Get part of payload
        if ((i + 1) * MAX_ICMP_PAYLOAD_SIZE < len(icmp_total_payload)):
            icmp_part_payload = icmp_total_payload[i * MAX_ICMP_PAYLOAD_SIZE:(i + 1) * MAX_ICMP_PAYLOAD_SIZE]
        else:
            icmp_part_payload = icmp_total_payload[i * MAX_ICMP_PAYLOAD_SIZE:]

        # Construct message
        icmp_msg = icmp_type + icmp_code + icmp_checksum + icmp_part_payload

        # Add message to collection
        icmp_msg_collection.append(icmp_msg)

    return icmp_msg_collection

def main():
    host = "127.0.0.1"
    port = 50007

    sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sockfd.bind((host, port))


    icmp_msg_collection = create_ICMP_message(47, 0, "HE")
    
    for icmp_msg in icmp_msg_collection:
        sockfd.sendto(icmp_msg, (host, port))




if (__name__ == "__main__"):
    main()