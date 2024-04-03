import struct

class ICMP:
    HEADER_SIZE = 8

    def __init__(self, type: int, code: int, checksum: int = 0, extended_header: int = 0, payload: bytes | None = None):
        self.type = type
        self.code = code
        self.checksum = checksum
        self.extended_header = extended_header
        self.payload = payload

    @classmethod
    def from_message(cls, message: bytes):
        icmp_header = message[:8]
        icmp_payload = message[8:]

        # Unpack the header
        icmp_type, icmp_code, icmp_checksum, icmp_extended_header = struct.unpack(">BBHL", icmp_header)

        return cls(icmp_type, icmp_code, icmp_checksum, icmp_extended_header, icmp_payload)
    
    def __str__(self) -> str:
        print_msg = "\nICMP Packet\n"
        print_msg += f'- Type: {self.type}\n'
        print_msg += f'- Code: {self.code}\n'
        print_msg += f'- Checksum: {self.checksum}\n'
        print_msg += f'- Extended header: {self.extended_header}'

        return print_msg
    
    def create_message(self, payload: bytes):
        # Recalculate the checksum
        self.checksum = 0 # Just 0 for now

        return int.to_bytes(self.type, 1, 'big') + int.to_bytes(self.code, 1, 'big') + int.to_bytes(self.checksum, 2, 'big') + int.to_bytes(self.extended_header, 4, 'big') + payload
        
