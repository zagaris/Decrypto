#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "crypto.h"

/*
 * Default server port
 */
#define DEFAULT_PORT	6000

/*
 * prints the usage message
 */
void usage(void) {
	printf(
	    "\n"
	    "Usage:\n"
	    "    server [-p port]\n"
	    "    server -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    "  -p  port       Server's port\n"
	    "  -h             This help message\n"
	);
	exit(EXIT_FAILURE);
}

/* Function that continouesly responds to the client.*/
void response (int socket_fd, unsigned char *aes_key, unsigned char *iv)
{
        unsigned char plaintext[BUFLEN];
        unsigned int plain_len = 0;
        unsigned char ciphertext[BUFLEN];
        unsigned int cipher_len = 0;

    	/* infinite loop for chat */
    	for (;;) {
			bzero(plaintext, BUFLEN);
        	bzero(ciphertext, BUFLEN);

        	/* read the message from the client and copy it in buffer */
        	read(socket_fd, ciphertext, sizeof(ciphertext));

			cipher_len = strlen((const char *) ciphertext);
        	/* print buffer which contains the client contents */

        	printf("---------------MESSAGE IN 16-BIT ANALYSIS------------------\n");
			BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len);
			printf("-----------------------------------------------------------\n");


			/* Decryption Phase... */
			plain_len = aes_decrypt(ciphertext, cipher_len, aes_key, iv, plaintext);
			plaintext[plain_len] = '\0';
			printf("Decrypted message: [%s].\n\n", plaintext);
        	write(socket_fd, plaintext, sizeof(plaintext));

        	/* if message contains "quit" then server exit and the session has ended. */
        	if (strstr((const char *) plaintext,"quit")) {
            		printf("Server Exit...\n");
            		break;
        	}
    	}
}



/*
 * simple chat server with RSA-based AES
 * key-exchange for encrypted communication
 */
int main(int argc, char *argv[]) {

	unsigned char iv[16];
	int server_socket;			/* My SERVER SOCKET 	*/
	int cfd;					/* comm file descriptor */
	int port;					/* server port		  	*/
	int opt;					/* cmd options		  	*/
	int plain_len;				/* plaintext size	  	*/
	int cipher_len;				/* ciphertext size	  	*/
	struct sockaddr_in srv_addr;		/* server socket address  */
	unsigned char *aes_key;				/* AES key		  		  */
	unsigned char plaintext[BUFLEN];	/* plaintext buffer	  	  */
	unsigned char ciphertext[BUFLEN];	/* plaintext buffer	  	  */
	RSA *s_prv_key;						/* server private key	  */
	RSA *c_pub_key;						/* client public key	  */

	cfd = -1;
	port = DEFAULT_PORT;
	memset(&srv_addr, 0, sizeof(srv_addr));


	/* get options */
	while ((opt = getopt(argc, argv, "p:h")) != -1) {
		switch (opt) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* socket init */
	server_socket = socket(AF_INET, SOCK_STREAM, 0);

	/*
	 * this will save them from:
	 * "ERROR on binding: Address already in use"
	*/
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = INADDR_ANY;
	srv_addr.sin_family = AF_INET;

	if (bind(server_socket, (struct sockaddr *) &srv_addr, sizeof(srv_addr)) != 0)
		ERRX(1, "ERROR on binding: Address already in use.\n");

	/*
	 * bind and listen the socket
	 * for new client connections
	*/

	listen(server_socket, 5);

	/* load keys */
	s_prv_key = rsa_read_key(S_PRV_KF);
	c_pub_key = rsa_read_key(C_PUB_KF);

	printf("The client has arrived! So I start!\n");
	if (s_prv_key != NULL && c_pub_key != NULL) {
		printf("All set! I have loaded my Server Private Key and the Client's Public Key!\n");
	}
	else {
		close(server_socket);
		ERRX(1, "Error at loading the RSA keys properly!\n");
	}

	/* accept a new client connection */
	cfd = accept(server_socket, NULL, NULL);

	/* wait for a key exchange init */

	printf("I am expecting the init-ciphertext!\n");
	read(cfd, ciphertext, 512);
	printf("I fetched the following ciphertext\n----------------------------------------\n");
	print_hex(ciphertext, 512);

	plain_len = rsa_pub_priv_decrypt(ciphertext, 512, c_pub_key, s_prv_key, plaintext);
	printf("Decrypted message is: [%s] with length: [%d]!\n", plaintext, plain_len);

	if (strcmp((const char *) plaintext, "hello")) {
		ERRX(1, "Wrong initialization message!");
		close(server_socket);
	}

    aes_key = malloc(sizeof(char) * 32);
    aes_key = aes_read_key();
	printf("Welcome! I am going to encypt the AES key:[%s].\n", aes_key);
	cipher_len = rsa_pub_priv_encrypt(aes_key, strlen((const char *) aes_key), c_pub_key, s_prv_key, ciphertext);

	if (cipher_len == -1)
		ERRX(1, "Something went wrong with the AES encryption!\n");

	printf("Encrypted AES Key bellow!\n-------------------------------------------\n");
	print_hex(ciphertext, cipher_len);

	/* send the AES key */
	write(cfd, ciphertext, cipher_len);

	read(cfd, iv, 16);

	printf("Client sent me the following IV.\n--------------------------------------------------\n");
	print_hex(iv, 16);
	response(cfd, aes_key, iv);

	/* cleanup */
	RSA_free(s_prv_key);
	RSA_free(c_pub_key);

	close(server_socket);

	return 0;
}

/* EOF */
