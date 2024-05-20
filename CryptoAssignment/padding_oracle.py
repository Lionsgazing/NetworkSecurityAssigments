import requests
from math import floor
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class PaddingOracle: 
    def __init__(self):
        self.get_token_addr = "http://localhost:5000" #"https://cbc-rsa.syssec.dk:8000" #"http://localhost:5000" 
        self.test_token_addr = "http://localhost:5000/quote"#"https://cbc-rsa.syssec.dk:8000/quote" #"http://localhost:5000/quote"

    def oracle(self, iv: bytes, block: bytes):
        # Create token with the iv and block
        token = iv + block

        # Create request and attach cookie with token
        cookie = {"authtoken": token.hex()}
        r = requests.get(self.test_token_addr, cookies=cookie)

        # Check response against some known error responses.
        if (r.content == b'Padding is incorrect.' or r.content == b'PKCS#7 padding is incorrect.' or  r.content == b'Zero-length input cannot be unpadded'): #r.content == b'No quote for you!' or
            return False
        else:
            return True
        
    def __report_progress(self, current_iv: bytes, i_block_byte: int, i_block: int, block_size: int, last: bool = False):
        # Create iv showcase msg
        prestr = f'Block {i_block}:           '

        # Create iv showcase tracker cursor
        iv_hex = current_iv.hex()
        formatted_iv = ""
        for i in range(block_size):
            hi = i * 2
            if (i == block_size - i_block_byte):
                formatted_iv += f'\033[4m\033[91m{iv_hex[hi]}{iv_hex[hi+1]}\033[0;0m'
            elif (i > block_size - i_block_byte):
                formatted_iv += f'\033[92m{iv_hex[hi]}{iv_hex[hi+1]}\033[0;0m'
            else:
                formatted_iv += iv_hex[hi] + iv_hex[hi+1]

        print(f'\r{prestr}{formatted_iv}', end="")

        if (last and i_block_byte >= block_size):
            # Because of some weird behaviour we put a blank str down.
            print("\r" + " " * (len(prestr) + len(formatted_iv)), end="")
            
            # Print formatted version
            formatted_iv = f'\033[92m{iv_hex}\033[0;0m'
            print(f'\r{prestr}{formatted_iv}\n', end="")

    def __report_block_dec_result(self, dec: bytes, i_block: int):
        prestr = f'DEC-Block {i_block}:       '
        formatted_iv = f'\033[92m{dec.hex()}\033[0m'
        print(f'{prestr}{formatted_iv}')

    def __report_block_enc_result(self, enc: bytes, i_block: int):
        prestr = f'ENC-Block {i_block}:       '
        formatted_iv = f'\033[92m{enc.hex()}\033[0m'
        print(f'{prestr}{formatted_iv}')
        
    def __report_block_plaintext_result(self, plaintext: bytes, i_block: int):
        prestr = f'Plaintext-Block {i_block}: '
        formatted_iv = f'\033[92m{plaintext.hex()}\033[0m'
        print(f'{prestr}{formatted_iv}')
        print("-" * (len(prestr) + len(formatted_iv)))

    def __report_block_ciphertext_result(self, ciphertext: bytes, i_block: int):
        prestr = f'CiphertextBlock {i_block}: '
        formatted_iv = f'\033[92m{ciphertext.hex()}\033[0m'
        print(f'{prestr}{formatted_iv}')
        print("-" * (len(prestr) + len(formatted_iv)))
    
    def __determine_block_count(self, iv_ciphertext: bytearray, block_size: int):
        # Get raw block count and floor it.
        return floor(len(iv_ciphertext) / block_size)
    
    def __to_blocks(self, input: bytearray, block_size: int, block_count: int):
        blocks: list[bytearray] = [bytearray()] * block_count
        
        for i in range(block_count):
            blocks[i] = input[block_size * i: (block_size * (i + 1))]
            
        return blocks
    
    def padding_oracle_block(self, block: bytearray, block_size: int, i_block: int):
        # Create block with 0's
        zero_iv = bytearray([0] * block_size)

        # Go through each byte
        for i_byte in range(1, block_size + 1):
            #XOR each byte in zero_iv with byte postion i_byte.
            padding_iv = [i_byte ^ byte for byte in zero_iv]

            # Go through each value
            for value in range(256):
                padding_iv[-i_byte] = value
                iv = bytes(padding_iv)

                # Debug
                self.__report_progress(iv, i_byte, i_block, block_size)
                
                # Test with oracle
                if (self.oracle(iv, block)):
                    if (i_byte == 1):
                        padding_iv[-2] ^= 1
                        iv = bytes(padding_iv)

                        if (not self.oracle(iv, block)):
                            continue
                    # Debug
                    self.__report_progress(iv, i_byte, i_block, block_size, True)

                    break
            # Result found so store it in the zero_iv.
            zero_iv[-i_byte] = i_byte ^ value

        # Return when full of results as the decrypted block
        return zero_iv


    def decrypt(self, iv_ciphertext: bytearray, block_size: int):
        # Find block count
        block_count = self.__determine_block_count(iv_ciphertext, block_size)
        # Convert iv_chiphertext to blocks
        blocks = self.__to_blocks(iv_ciphertext, block_size, block_count)
        # Do decryption using oracle
        iv = blocks[0]
        result = b''

        print("CBC-Padding-Oracle Attack - Decryption")
        print("-------------------------")
        print(f"- IV + Ciphertext: {iv_ciphertext.hex()}")
        print(f"- Block size: {block_size}")
        print(f"- Block count: {block_count}")
        print("-------------------------")
        print("Performing attack...")
        print("-------------------------")
        print(f"Block 0 / IV:      \033[92m{iv.hex()}\033[0;0m")
        print(f'------------------------------------------------------------')
        
        # Process each block
        for i_block in range(1, len(blocks)):
            block = blocks[i_block]
            # Get DEC block with padding oracle.
            decrypted_block = self.padding_oracle_block(block, block_size, i_block)
            # Debug
            self.__report_block_dec_result(bytes(decrypted_block), i_block)
            # Calc plaintext block from the other blocks.
            plaintext_block = bytes(iv_byte ^ decrypted_block_byte for iv_byte, decrypted_block_byte in zip(iv, decrypted_block))
            # Debug
            self.__report_block_plaintext_result(plaintext_block, i_block)
            # Add block to result.
            result += plaintext_block
            # Set current block as next iv.
            iv = block

        # Debug
        print(f"Plaintext: {result.hex()}")
        print(f'Result: \033[96m{result.decode(encoding="utf-8")}\033[0;0m')

        return result
    
    def encrypt(self, plaintext: bytearray, block_size: int):
        # Pad message.
        plaintext = pad(plaintext, block_size)
        # Find block count
        block_count = self.__determine_block_count(plaintext, block_size)
        # Convert plaintext to blocks
        plaintext_blocks = self.__to_blocks(plaintext, block_size, block_count)
        # Create ciphertext_block storage
        ciphertext_blocks = [bytes()] * (block_count + 1) # Add space for IV.
        # Insert random value at last ciphertext_block.
        ciphertext_blocks[len(ciphertext_blocks) - 1] = bytes(b'\x00' * block_size)

        print("CBC-Padding-Oracle Attack - Encryption")
        print("-------------------------")
        print(f"- Plaintext: {plaintext.decode()}")
        print(f"- Block size: {block_size}")
        print(f"- Block count: {block_count}")
        print("-------------------------")
        print("Performing attack...")
        print("-------------------------")

        for i_plaintext_block in range(len(plaintext_blocks)):
            # Reversed counter
            i_reversed_plaintext_block = len(plaintext_blocks) - 1 - i_plaintext_block
            # Get plaintext block
            plaintext_block = plaintext_blocks[i_reversed_plaintext_block]
            # Get ENC ciphertext block through padding oracle.
            enc_ciphertext_block = self.padding_oracle_block(ciphertext_blocks[i_reversed_plaintext_block + 1], block_size, i_reversed_plaintext_block)
            # Debug
            self.__report_block_enc_result(bytes(enc_ciphertext_block), i_reversed_plaintext_block)
            # Get the ciphertext block.
            ciphertext_blocks[i_reversed_plaintext_block] = bytes(plaintext_byte ^ enc_ciphertext_byte for plaintext_byte, enc_ciphertext_byte in zip(plaintext_block, enc_ciphertext_block))
            # Debug
            self.__report_block_ciphertext_result(ciphertext_blocks[i_reversed_plaintext_block], i_reversed_plaintext_block)

        # Generate the result from the blocks.
        result = b''
        for ciphertext_block in ciphertext_blocks:
            result += ciphertext_block
        print(f"Ciphertext: \033[96m{result.hex()}\033[0;0m")

        return result
