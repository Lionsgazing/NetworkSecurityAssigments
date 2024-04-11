from Crypto.Cipher import ChaCha20_Poly1305, AES

class SecurePayload:
    
    HEADER_SIZE = 2 # Bytes

    def __init__(self, cipher_type: str, key: str, nonce: bytes | None = None):
        self.key = key
        self.cipher_type = cipher_type
        self.IsReadyChiper = False

        self.create_cipher(self.cipher_type, self.key, nonce=nonce)


    def create_cipher(self, cipher_type: str, key: str, nonce: bytes | None = None):
        # Create cipher
        if (cipher_type == "ChaCha20_Poly1305"):
            self.cipher = ChaCha20_Poly1305.new(key=bytes(key, encoding='utf-8'), nonce=nonce)
            self.nonce_len = 12
            self.MAC_tag_len = 16
            self.IsReadyChiper = True
        else:
            self.IsReadyChiper = False

    def encrypt(self, payload: bytes, debug_info: bool = False):
        if (not self.IsReadyChiper):
            return
        
        # Encrypt plaintext to ciphertext and get MAC tag.
        ciphertext, MAC_tag = self.cipher.encrypt_and_digest(payload)

        # Header
        header = int.to_bytes(self.nonce_len, 1, 'big') + int.to_bytes(self.MAC_tag_len, 1, 'big')

        # Structure payload
        encrypted_payload = header + self.cipher.nonce + MAC_tag + ciphertext

        if (debug_info):
            print("Encrypter Info")
            print(f'- Nonce size: {len(self.cipher.nonce)}')
            print(f'- Nonce: {self.cipher.nonce.hex()}')
            print(f'- MAC tag size: {len(MAC_tag)}')
            print(f'- MAC tag: {MAC_tag.hex()}')
            print(f'- Ciphertext: {ciphertext.hex()}')

        return encrypted_payload
    
    def disect_payload(self, payload: bytes):
        payload_header = payload[0:self.HEADER_SIZE]

        payload_nonce_size = payload_header[0]
        payload_MAC_tag_size = payload_header[1]

        index_offset = self.HEADER_SIZE
        payload_nonce = payload[index_offset:index_offset + payload_nonce_size]
        index_offset += payload_nonce_size

        payload_MAC_tag = payload[index_offset:index_offset + payload_MAC_tag_size]
        index_offset += payload_MAC_tag_size

        payload_ciphertext = payload[index_offset:]

        return payload_nonce_size, payload_MAC_tag_size, payload_nonce, payload_MAC_tag, payload_ciphertext

    def decrypt(self, payload: bytes, debug_info: bool = False):       
        if (not self.IsReadyChiper):
            return

        # Extract info
        payload_nonce_size, payload_MAC_tag_size, payload_nonce, payload_MAC_tag, payload_ciphertext = self.disect_payload(payload)

        # Check payload nonce against cipher nonce. If not equal create a new cipher with given nonce
        if (not payload_nonce == self.cipher.nonce):
            self.create_cipher(self.cipher_type, self.key, payload_nonce)

        # Do decryption
        plaintext = self.cipher.decrypt_and_verify(payload_ciphertext, payload_MAC_tag)

        if (debug_info):
            print("\nDecrypter Info")
            print(f'- Nonce size: {payload_nonce_size}')
            print(f'- Nonce: {payload_nonce.hex()}')
            print(f'- MAC tag size: {payload_MAC_tag_size}')
            print(f'- MAC tag: {payload_MAC_tag.hex()}')

        return plaintext


        
        
        
