### How to run CBC Padding Oracle attack
The file `main.py` and `padding_oracle.py` should both be in the same directory.

The local_test_server used is also included and can simply be started by being in the local_test_server directory and running the following command `python -m flask -app main.py run`.

With the local server running a simple `python ./main.py` command should do the trick and run the CBC Padding Oracle attack on the local server.

The target server is set to the following out of the box:
- Get token address: `http://localhost:5000`
- Test token address: `http://localhost:5000/quote`

Originally the cbc-rsa-syssec server was used but as of this time that server is not running anymore and therefore the local server is bundled with the code here.

These addresses can both be changed under the main function in `main.py` if the user want to use a different target.

The only packages used are:
- requests
- copy
- math
- collections

Tested with Python version 3.12.1 on WSL2 running Ubuntu 22.04.3 LTS