import socket

def main():

    host = ""
    port = 1200

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.bind((host, port))

    isRunning = True

    while(isRunning):
        msg, addr = sock.recvfrom(256)
        print(f'{addr} : {msg.decode(encoding="utf-8")}')

if (__name__ == "__main__"):
    main()