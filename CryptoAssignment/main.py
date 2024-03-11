from padding_oracle import CBCPaddingOracle
import requests
from copy import copy

def main():
    get_token_addr = "https://cbc-rsa.syssec.dk:8000" #"http://localhost:5000" 
    test_token_addr = "https://cbc-rsa.syssec.dk:8000/quote" #"http://localhost:5000/quote"

    print(f"Target get token address: {get_token_addr}")
    print(f"Target test token address: {test_token_addr}")

    def oracle(iv: bytes, block: bytes):
        # Create token with the iv and block
        token = iv + block

        # Create request and attach cookie with token
        cookie = {"authtoken": token.hex()}
        r = requests.get(test_token_addr, cookies=cookie)

        # Check response against some known error responses.
        if (r.content == b'Padding is incorrect.' or r.content == b'PKCS#7 padding is incorrect.' or  r.content == b'Zero-length input cannot be unpadded'): #r.content == b'No quote for you!' or
            return False
        else:
            return True

    # Establish baseline ciphertext
    r = requests.get(get_token_addr)
    ciphertext_str = r.cookies["authtoken"]
    ciphertext_bytes_baseline = bytearray.fromhex(ciphertext_str)

    # Find block size by changing bytes from the iv end of the ciphertext until we get a padding error. 
    # We know that the ciphertext contains an IV in the front.
    ciphertext_bytes = copy(ciphertext_bytes_baseline)
    block_size = 0
    for i in range(len(ciphertext_bytes)):
        ciphertext_bytes[i] ^= 0x25 # A random value to filp some of the bits in the ciphertext byte.
        r = requests.get(test_token_addr, cookies={"authtoken": ciphertext_bytes.hex()})
        if (r.content != b'No quote for you!'):
            break
        else:
            block_size += 1

    # Break encryption using the CBC Padding Oracle
    CBCBreak = CBCPaddingOracle(copy(ciphertext_bytes_baseline), block_size, oracle)
    result = CBCBreak.attack()

if (__name__ == "__main__"):
    main()