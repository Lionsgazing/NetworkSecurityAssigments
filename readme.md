### How to run CBC Padding Oracle attack
The file `main.py` and `padding_oracle.py` should both be in the same directory.

A simple `python ./main.py` command should do the trick and run the CBC Padding Oracle attack.

The target server is set to the following out of the box:
- Get token address: `https://cbc-rsa.syssec.dk:8000`
- Test token address: `https://cbc-rsa.syssec.dk:8000/quote`

These addresses can both be changed under the main function in `main.py` if the user want to use a different target.

The only packages used are:
- requests
- copy
- math
- collections

Tested with Python version 3.12.1 on WSL2 running Ubuntu 22.04.3 LTS