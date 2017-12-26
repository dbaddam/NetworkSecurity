-----------------------------------------------------------------------------------------------------------------------------------------------------------

PLUGBOARD PROXY:
-----------

pbproxy.c has the capability to act as both proxy server and proxy client.

Example commands to run pbproxy:

server:
./pbproxy -k mykey -l 22000 localhost 10000

client:
./pbproxy -k mykey 127.0.0.1 22000


If the key file name is not provided incorrect the program returns.
If there is no -k option in the input argument, it assumes a predifined key on both server and client side.

In the server command above there should be a simple server listening on 10000 which an echo for test purposes. The proxy server is now listening on 22000 through which clients are connected.

On client side, it connects to 127.0.0.1 which is the IP of pbproxy server and 22000, the port on which pbproxy server is listening on.

Data is be encrypted/decrypted using AES in CTR mode (bi-directional communication) using openSSL library functions and I used the the above reference for understanding purposes.

When a client and server are connected for first time, they have IV handshake, where they exchange their IVs which they use for further encryption/decryption purposes.Proxy client sends an encryption IV first and proxy server receives it and uses for decrytion and viceversa.

I have used the select function for IO multiplexing.
Proxy client simultaneously talks to both stdin/stdout and proxy server. 
Proxy server simultaneously talks to both client and protected server.


Tested Environment:
Ubuntu 16.04.3 LTS gcc version 5.4.0.

Developed Environment:
ProductName:	Mac OS X
ProductVersion:	10.12.6
BuildVersion:	16G29

REFERENCES:
http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
www.stackoverflow.com
