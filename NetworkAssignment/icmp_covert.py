import socket

def main():
    host = "127.0.0.1"
    port = 50007

    sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sockfd.bind((host, port))

    sockfd.sendto(b'boi', (host, port))




if (__name__ == "__main__"):
    main()