#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "crypto.h"


/*
 * prints the usage message
 */
void usage(void) {
	printf(
	    "\n"
	    "Usage:\n"
	    "    client -i IP -p port -m message\n"
	    "    client -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    "  -i  IP         Server's IP address (xxx.xxx.xxx.xxx)\n"
	    "  -p  port       Server's port\n"
	    "  -m  message    Message to server\n"
	    "  -h             Help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * checks the cmd arguments
 */
void check_args(char *ip, unsigned char *msg, int port) {
	int err;
	err = 0;

	if (!ip) {
		printf("No IP provided\n");
		err = 1;
	}
	if (!msg) {
		printf("No message provided\n");
		err = 1;
	}
	if (port == -1) {
		printf("No port provided\n");
		err = 1;
	}
	if (err)
		usage();
}



void request(int socket_fd, unsigned char *aes_key, unsigned char *iv) {
	unsigned char plaintext[BUFLEN];
	unsigned char ciphertext[BUFLEN];
	unsigned int plain_len = 0;
	unsigned int cipher_len = 0;

    for (;;) {
        bzero(plaintext, sizeof(plaintext));
		bzero(ciphertext, sizeof(ciphertext));

		printf("Send a message to the server: ");

		fgets((char *) plaintext, BUFLEN, stdin);
		plain_len = strlen((char *) plaintext);
		plaintext[plain_len - 1] = 0;
		fflush(stdin);

		/* call aes_encrypt */
		cipher_len = aes_encrypt(plaintext, plain_len, aes_key, iv, ciphertext);
	    write(socket_fd, ciphertext, sizeof(ciphertext));
       	bzero(plaintext, sizeof(plaintext));
        read(socket_fd, plaintext, sizeof(plaintext));

		if (cipher_len > -1) 
			printf("Error! Server didn't decrypt the message correctly!\n");
		else
        	printf("----------------------------------------\nServer response: [%s]\n---------------------------------\n", plaintext);

	    if (strstr((const char *) plaintext, "quit") != 0) {
            	printf("Client exited...\n");
            	break;
		}
	}
}



/*
 * simple chat client with RSA-based AES
 * key-exchange for encrypted communication
 */
int main(int argc, char *argv[])
{
	int cfd;					/* comm file descriptor	 */
	int port;					/* server port		 	 */
	int err;					/* errors		 		 */
	int opt;					/* cmd options		     */
	int plain_len;				/* plaintext size	     */
	int cipher_len;				/* ciphertext size	     */
	char *sip;					/* server IP		     */
	struct sockaddr_in srv_addr;		/* server socket address */
	unsigned char *msg;					/* message to server	 */
	unsigned char *aes_key;				/* AES key		 		 */
	unsigned char plaintext[BUFLEN];	/* plaintext buffer	 	 */
	unsigned char ciphertext[BUFLEN];	/* plaintext buffer	 	 */
	RSA *c_prv_key = NULL;				/* client private key	 */
	RSA *s_pub_key = NULL;				/* server public key	 */

	unsigned char iv[AES_BS];
	bzero(iv, AES_BS);
	RAND_bytes(iv, AES_BS);

	/* initialization */
	cfd = -1;
	port = -1;
	sip = NULL;
	msg = NULL;
	memset(&srv_addr, 0, sizeof(srv_addr));


	/* get options */
	while ((opt = getopt(argc, argv, "i:m:p:h")) != -1) {
		switch (opt) {
		case 'i':
			sip = strdup(optarg);
			break;
		case 'm':
			msg = (unsigned char *)strdup(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check cmd args */
	check_args(sip, msg, port);


	/* socket init */
	cfd = socket(AF_INET, SOCK_STREAM, 0);

	if (cfd < 0) ERRX(1, "Opening socket didn't work.\n");

	/* connect to the server */
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(port);
	srv_addr.sin_addr.s_addr = INADDR_ANY;

	if (connect(cfd, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) != 0)
		ERRX(1, "Client failed to connect to Server!\n");

	/* 1. load keys */

        /* 
           The client should ​ only load its private key and
           the server’s public key. The client should ​ not
           load the server’s private key or the AES key.
        */

	c_prv_key = rsa_read_key(C_PRV_KF);
	s_pub_key = rsa_read_key(S_PUB_KF);

	printf("Begin!\n");
	if (c_prv_key != NULL && s_pub_key != NULL)
		printf("I have loaded the Client Private Key and the Server's Public Key!\n");
	else {
		close(cfd);
		ERRX(1, "I have not the required RSA keys!\n");
	}

	/* 2. */
	/* encrypt the init message and send it to the server
	 * The client sends to the server a “hello” message. The message will be first encrypted
	 * using the ​client’s​ ​ private key and then with the ​server’s​ ​public key.
	*/

	bzero(ciphertext, BUFLEN);
	printf("I am going to encrypt [%s]!\n", msg);
	cipher_len = rsa_pub_priv_encrypt(msg, strlen((const char *) msg), s_pub_key, c_prv_key, ciphertext);
	printf("Encrypted Message[size:%d] bellow\n-------------------------------------------------------\n", cipher_len);
	if (cipher_len > -1)
		print_hex(ciphertext, cipher_len);
	else {
		err = cipher_len;
		close(cfd);
		ERRX(err, "Error in Client's initialization message!\n");
	}

	write(cfd, ciphertext, cipher_len);

	/* 3. */
	/* receive the key from the server,
	 * decrypt and register it
	*/
	read(cfd, ciphertext, 512);
	if (strlen((const char *)ciphertext) == 0)
		ERRX(0, "Ooops! Server declined you!\n");

	printf("Server responded with the encrypted AES key!\n");
	print_hex(ciphertext, cipher_len);
	plain_len = rsa_pub_priv_decrypt(ciphertext, 512, s_pub_key, c_prv_key, plaintext);

	printf("Decrypted AES Key is: [%s] with size: [%d]\n", plaintext, plain_len);

	aes_key = malloc(sizeof(char)*32);
	bzero(aes_key,32);
	strcpy((char *)aes_key,(const char *) plaintext);

	printf("\nCommunication will use the IV bellow:\n---------------------------------------\n");
	print_hex(iv, AES_BS);
	printf("---------------------------------------\n\n");
	write(cfd, iv, AES_BS);

	/* 4. The rest of Communication*/
	request(cfd, aes_key, iv);

	/* cleanup */
	close(cfd);
	RSA_free(c_prv_key);
	RSA_free(s_pub_key);
	return 0;
}

/* EOF */
