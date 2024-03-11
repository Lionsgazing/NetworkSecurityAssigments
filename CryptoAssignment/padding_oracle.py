from collections.abc import Callable 
from math import floor

class CBCPaddingOracle:
    def __init__(self, iv_ciphertext: bytearray, block_size: int, oracle: Callable[[bytearray, bytearray], bool]):
        # Save given information
        self._oracle = oracle
        self._iv_ciphertext = iv_ciphertext
        self._block_size = block_size

        #  Determine block count
        self._block_count = self.__determine_block_count(self._iv_ciphertext, self._block_size)

        # Get blocks
        self._blocks = self.__ciphertext_to_blocks(self._iv_ciphertext, self._block_size, self._block_count)

    def __determine_block_count(self, iv_ciphertext: bytearray, block_size: int):
        # Get raw block count and floor it.
        return floor(len(iv_ciphertext) / block_size)
        

    def __ciphertext_to_blocks(self, iv_ciphertext: bytearray, block_size: int, block_count: int):
        blocks: list[bytearray] = [bytearray()] * block_count
        for i in range(block_count):
            blocks[i] = iv_ciphertext[block_size * i: (block_size * (i + 1))]
            
        return blocks
    
    def __report_progress(self, current_iv: bytes, i_block_byte: int, i_block: int, last: bool = False):
        # Create iv showcase msg
        prestr = f'Block {i_block}:           '

        # Create iv showcase tracker cursor
        iv_hex = current_iv.hex()
        formatted_iv = ""
        for i in range(self._block_size):
            hi = i * 2
            if (i == self._block_size - i_block_byte):
                formatted_iv += f'\033[4m\033[91m{iv_hex[hi]}{iv_hex[hi+1]}\033[0;0m'
            elif (i > self._block_size - i_block_byte):
                formatted_iv += f'\033[92m{iv_hex[hi]}{iv_hex[hi+1]}\033[0;0m'
            else:
                formatted_iv += iv_hex[hi] + iv_hex[hi+1]

        print(f'\r{prestr}{formatted_iv}', end="")

        if (last and i_block_byte >= self._block_size):
            # Because of some weird behaviour we put a blank str down.
            print("\r" + " " * (len(prestr) + len(formatted_iv)), end="")
            
            # Print formatted version
            formatted_iv = f'\033[92m{iv_hex}\033[0;0m'
            print(f'\r{prestr}{formatted_iv}\n', end="")

    def __report_block_dec_result(self, correct_iv: bytes, i_block: int):
        prestr = f'DEC-Block {i_block}:       '
        formatted_iv = f'\033[92m{correct_iv.hex()}\033[0m'
        print(f'{prestr}{formatted_iv}')
        
    def __report_block_plaintext_result(self, plaintext: bytes, i_block: int):
        prestr = f'Plaintext-Block {i_block}: '
        formatted_iv = f'\033[92m{plaintext.hex()}\033[0m'
        print(f'{prestr}{formatted_iv}')
        print("-" * (len(prestr) + len(formatted_iv)))

    def __process_block(self, block: bytearray, i_block: int):
        #Flags
        flag_found_match = False
        #Storage values
        zero_iv = [0] * self._block_size
        for i_block_byte in range(1, self._block_size + 1):
            # Load padding_iv from zero_iv and apply i_block_byte as offset on the current values.
            padding_iv = [i_block_byte ^ b for b in zero_iv]
            for val in range(256):
                # Assign value and convert the padding_iv to the bytes format.
                padding_iv[-i_block_byte] = val
                iv = bytes(padding_iv)
                self.__report_progress(iv, i_block_byte, i_block)
                # Check if value is correct against the oracle
                if (self._oracle(iv, block)):
                    # Check for possible edge case
                    if (i_block_byte == 1):
                        padding_iv[-2] ^= 1
                        iv = bytes(padding_iv)
                        if (not self._oracle(iv, block)):
                            continue #False positive
                    # Raise found match flag.
                    flag_found_match = True
                    self.__report_progress(iv, i_block_byte, i_block, True)
                    break
            # Check if a match was found. If not raise execption since something is not working as it should.
            if (flag_found_match == False):
                raise Exception("Value match not found. Check if oracle is working correctly!")
            # Reset flag for next iteration
            flag_found_match = False
            # Append found value to zero_iv at byte location and xor the i_block_byte as offset.
            zero_iv[-i_block_byte] = i_block_byte ^ val
        return zero_iv

    def attack(self):
        #Use created blocks
        iv = self._blocks[0]

        # Create result variable
        result = b''

        print("CBC-Padding-Oracle Attack")
        print("-------------------------")
        print(f"- IV + Ciphertext: {self._iv_ciphertext.hex()}")
        print(f"- Block size: {self._block_size}")
        print(f"- Block count: {self._block_count}")
        print("-------------------------")
        print("Performing attack...")
        print("-------------------------")
        print(f"Block 0 / IV:      \033[92m{iv.hex()}\033[0;0m")
        print(f'------------------------------------------------------------')

    def attack(self):
        #Use created blocks
        iv = self._blocks[0]
        # Create result variable
        result = b''
        # Perform attack on each block
        for i_block in range(1, len(self._blocks)):
            # Get block and perform attack on the block
            block = self._blocks[i_block]
            decrypted_block = self.__process_block(block, i_block)
            # Report status to console
            self.__report_block_dec_result(bytes(decrypted_block), i_block)
            # Convert the decrypted block to plaintext using the IV.
            plaintext_block = bytes(iv_byte ^ decrypted_block_byte for iv_byte, decrypted_block_byte in zip(iv, decrypted_block))
            # Report plaintext version
            self.__report_block_plaintext_result(plaintext_block, i_block)
            # Append to result
            result += plaintext_block
            # Use the current block as the next iv.
            iv = block
        print(f"Plaintext: {result.hex()}")
        print(f'Result: \033[96m{result.decode(encoding="utf-8")}\033[0;0m')
        return result