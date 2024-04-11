### How to run
For the client and server to run the user must execute the following:
Client: `sudo pyhton ./icmp-client.py [IPV4-address]`
Server: `sudo python ./icmp-server.py`

Note that both has to be run as superuser because otherwise we cannot the access to the raw socket packets. This also means that pycryptodome has to be install as a superuser too with pip.