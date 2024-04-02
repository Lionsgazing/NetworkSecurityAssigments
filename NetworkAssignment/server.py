import socket

def unpack_IPV4_message(message: bytes): 
    ipv4_version_IHL_len = 1 # Byte
    ipv4_TOS_len = 1 # Byte
    ipv4_total_length_len = 2 # Bytes
    ipv4_identification_len = 2 # Bytes
    ipv4_flags_fragment_offset_len = 2 # Bytes
    ipv4_TTL_len = 1 # Byte
    ipv4_protocol_len = 1 # Byte
    ipv4_header_checksum_len = 2 # Bytes
    ipv4_source_addr_len = 4 # Bytes
    ipv4_dest_addr_len = 4 # Bytes


    # HMM perhaps a stuct.unpack instead of this?
    len_tracker = 0
    
    ipv4_version_IHL = message[len_tracker:len_tracker + ipv4_version_IHL_len]
    len_tracker += ipv4_version_IHL_len

    ipv4_TOS = message[len_tracker:len_tracker + ipv4_TOS_len]
    len_tracker += ipv4_TOS_len

    ipv4_total_length = message[len_tracker:len_tracker + ipv4_total_length_len]
    len_tracker += ipv4_total_length_len

    ipv4_identification = message[len_tracker:len_tracker + ipv4_identification_len]
    len_tracker += ipv4_identification_len

    ipv4_flags_fragment_offset = message[len_tracker:len_tracker + ipv4_flags_fragment_offset_len]
    len_tracker += ipv4_flags_fragment_offset_len

    ipv4_TTL = message[len_tracker:len_tracker + ipv4_TTL_len]
    len_tracker += ipv4_TTL_len

    ipv4_protocol = message[len_tracker:len_tracker + ipv4_protocol_len]
    len_tracker += ipv4_protocol_len

    ipv4_header_checksum = message[len_tracker:len_tracker + ipv4_header_checksum_len]
    len_tracker += ipv4_header_checksum_len

    ipv4_source_addr = message[len_tracker:len_tracker + ipv4_source_addr_len]
    len_tracker += ipv4_source_addr_len

    ipv4_dest_addr = message[len_tracker:len_tracker + ipv4_dest_addr_len]
    len_tracker += ipv4_dest_addr_len

    return message[len_tracker:]





def unpack_ICMP_message(message: bytes):
    icmp_type_len = 1 # Byte
    icmp_code_len = 1 # Byte
    icmp_checksum_len = 2 # Bytes

    # Do unpacking
    icmp_type = message[:icmp_type_len]
    icmp_code = message[icmp_type_len:icmp_type_len + icmp_code_len]
    icmp_checksum = message[icmp_type_len + icmp_code_len:icmp_type_len + icmp_code_len + icmp_checksum_len]

    icmp_payload = message[icmp_type_len + icmp_code_len + icmp_checksum_len:]

    return icmp_type, icmp_code, icmp_checksum, icmp_payload

    

def main():

    host = ""
    port = 50007

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((host, port))

    isRunning = True

    while(isRunning):
        msg, addr = sock.recvfrom(100)

        icmp_type, icmp_code, icmp_checksum, icmp_payload = unpack_ICMP_message(unpack_IPV4_message(msg))

        print(f'{addr} : {icmp_payload}')

if (__name__ == "__main__"):
    main()