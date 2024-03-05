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
        for i in range(len(iv_ciphertext)):
            blocks[i] = iv_ciphertext[block_size * i: (block_size * i + 1)]
            
        return blocks

    def __process_block(self):
        pass

    def attack(self, iv: bytearray, ciphertext: bytearray):
        #Create Message
        msg: bytearray = iv + ciphertext

        #
       
        pass