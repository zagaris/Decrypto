# Decrypto

Descrypto is a symmetric key mechanism for a secure chat server/client scenario, using the openSSL toolkit.


## Communication and Key Exchange Protocol between client and server


The client only loads it's private key and server's public key and the server only loads its private key, the client’s public key and the AES key.
So, the server and the client know the public key of each other. 

When the client wants to contact the server, the following process take place:

1) The client sends to the server a "hello" message. The message will be encrypted using the client's private key and then with the server's public key.

2) When the message is received from the server, it will be descrypted using the server's private key and then with the client's public key.

3) Now, if the message is decrypted correctly(the first message is "hello") the server will encrypt the AES key(it will be loaded from the aes_key.txt) and use the same steps as before to send it to the client i.e. encrypt it with the server's private key and then with the client's public key.

4) Then, the client will decrypt the message that contains the symmetric key by decrypting it with the client's private key and then with the server's public key and store it in a varriable in order to use it for the rest of the communication process.

5) After the above steps, the client and the server will use symmetric cryptography in order to encrypt/decrypt messages exhanged between them. The client will use the message obtained by the command line, encrypt it with the exchanged AES key and send it back to the server.The server is now able to decrypt the message with the AES key and print it on the screen.

The AES implementation uses AES-CBC 128 bit mode.


## Quick Start

Clone the repo and execute the Makefile.

```bash
https://github.com/zagaris/Decrypto
cd Decrypto
make all
```
You have to run the server executable first and then the client executable.
The default port for the server is 6000, but you can specify a different port via the -p parameter in the server executable

```bash
./server
./client -i 127.0.0.1 -p 6000 -m "hello"
```
Also, you can terminate the communication by sending the message `quit` to the server.
