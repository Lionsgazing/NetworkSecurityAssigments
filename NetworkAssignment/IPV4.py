import struct

class IPV4:
    HEADER_SIZE = 20

    def __init__(self, version: int, IHL: int, TOS: int, total_length: int, identification: int, flags: int, fragment_offset: int, TTL: int, protocol: int, header_checksum: int, source_addr: int, dest_addr: int, payload: bytes):
        self.version = version
        self.IHL = IHL
        self.TOS = TOS
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.TTL = TTL
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source_addr_raw = source_addr
        self.dest_addr_raw = dest_addr
        self.payload = payload

        # Format address
        self.source_addr = struct.unpack(">BBBB", int.to_bytes(self.source_addr_raw, 4, 'big'))
        self.dest_addr = struct.unpack(">BBBB", int.to_bytes(self.dest_addr_raw, 4, 'big'))
        

    @classmethod
    def from_message(cls, message: bytes):
        #IPV4 Premble total size: 20 Bytes
        ipv4_header = message[:20] # Extract first 20 bytes and unpack
        ipv4_payload = message[20:]

        # Unpack the header
        ipv4_version_IHL, ipv4_TOS, ipv4_total_length, ipv4_identification, ipv4_flags_fragment_offset, ipv4_TTL, ipv4_protocol, ipv4_header_checksum, ipv4_source_addr, ipv4_dest_addr = struct.unpack(">BBHHHBBHLL", ipv4_header)

        # Extract sub information
        ipv4_version = (ipv4_version_IHL & 0b11110000) >> 4
        ipv4_IHL = ipv4_version_IHL & 0b00001111

        ipv4_flags = (ipv4_flags_fragment_offset & 0b1110000000000000) >> 13
        ipv4_fragment_offset = ipv4_flags_fragment_offset & 0b0001111111111111

        return cls(ipv4_version, ipv4_IHL, ipv4_TOS, ipv4_total_length, ipv4_identification, ipv4_flags, ipv4_fragment_offset, ipv4_TTL, ipv4_protocol, ipv4_header_checksum, ipv4_source_addr, ipv4_dest_addr, ipv4_payload)

    def __str__(self) -> str:
        print_msg = "\nIPV4 Packet\n"
        print_msg += f'- Version: {self.version}\n'
        print_msg += f'- IHL: {self.IHL}\n'
        print_msg += f'- TOS: {self.TOS}\n'
        print_msg += f'- Total Length: {self.total_length}\n'
        print_msg += f'- Identification: {self.identification}\n'
        print_msg += '- Flags (binary): {0:b}\n'.format(self.flags)
        print_msg += f'- Fragment offset: {self.fragment_offset}\n'
        print_msg += f'- TTL: {self.TTL}\n'
        print_msg += f'- Protocol: {self.protocol}\n'
        print_msg += f'- Header checksum: {self.header_checksum}\n'
        print_msg += f'- Source Address: {self.source_addr}\n'
        print_msg += f'- Destination Address: {self.dest_addr}'

        return print_msg
