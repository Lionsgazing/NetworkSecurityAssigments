import socket

def main():

    host = "127.0.0.1"
    port = 50007

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind((host, port))

    isRunning = True

    while(isRunning):
        msg, addr = sock.recvfrom(1)
        print(f'{addr} : {msg.decode(encoding="utf-8")}')

if (__name__ == "__main__"):
    main()