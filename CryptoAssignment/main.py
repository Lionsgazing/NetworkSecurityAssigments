from padding_oracle import PaddingOracle
import requests
from copy import copy

def main():
    get_token_addr = "http://localhost:5000" #"https://cbc-rsa.syssec.dk:8000" #"http://localhost:5000" 
    test_token_addr = "http://localhost:5000/quote"#"https://cbc-rsa.syssec.dk:8000/quote" #"http://localhost:5000/quote"

    print(f"Target get token address: {get_token_addr}")
    print(f"Target test token address: {test_token_addr}")

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
    CBCBreak = PaddingOracle()
    
    # Decrypt msg first
    result = CBCBreak.decrypt(copy(ciphertext_bytes_baseline), block_size)    

    # Debug
    print("\nIsolate known 'secret' part of message:")

    # Decode bytes to string
    result_str = result.decode()
    # Split string by " and only save the middle part of the string. We already know that this is the secert message.
    plaintext_str = result_str.split('"')[1]
    
    # Debug
    print(f"Original plaintext: {result_str}")
    print(f"Isolated plaintext: \033[96m{plaintext_str}\033[0;0m\n")
    print("Now encrypt isolated plaintext and send it back to the server...\n")

    # Encode string back to bytes format
    plaintext = plaintext_str.encode()
    
    #plaintext = bytearray.fromhex(b'lol scrub'.hex())
    result = CBCBreak.encrypt(plaintext, block_size)
    #result = bytes(reversed(result))
    
    cookie = {"authtoken": result.hex()}
    r = requests.get(test_token_addr, cookies=cookie)
    print(f"\nServer response: \033[96m{r.content}\033[0;0m")

if (__name__ == "__main__"):
    main()