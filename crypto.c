#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>

/* error reporting helpers */
#define ERRX(ret, str) \
    do { fprintf(stderr, str "\n"); exit(ret); } while (0)
#define ERR(ret, str) \
    do { fprintf(stderr, str ": %s\n", strerror(errno)); exit(ret); } while (0)

/* buffer size */
#define BUFLEN	2048

/* key files*/
#define AES_KF		"keys/aes_key.txt"
#define S_PUB_KF	"keys/srv_pub.pem"
#define S_PRV_KF	"keys/srv_priv.pem"
#define C_PUB_KF	"keys/cli_pub.pem"
#define C_PRV_KF	"keys/cli_priv.pem"

/* AES block size */
#define AES_BS 16


/*
 * converts half printable hex value to integer
 */
int half_hex_to_int(unsigned char c) {

	if (isdigit(c))
		return c - '0';

	if ((tolower(c) >= 'a') && (tolower(c) <= 'f'))
		return tolower(c) + 10 - 'a';

	return 0;
}


/*
 * converts a printable hex array to bytes
 */
char *hex_to_bytes(char *input) {

	int i;
	char *output;

	output = NULL;
	if (strlen(input) % 2 != 0)
		ERRX(0, "reading hex string");

	output = calloc(strlen(input) / 2, sizeof(unsigned char));
	if (!output)
		ERRX(1, "h2b calloc");

	for (i = 0; i < strlen(input); i+= 2) {
		output[i / 2] = ((unsigned char)half_hex_to_int(input[i])) *
		    16 + ((unsigned char)half_hex_to_int(input[i + 1]));
	}

	return output;
}


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len) {

	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * retrieves an AES key from the key file
 */
unsigned char *aes_read_key(void) {
	unsigned char *aes_key = malloc(256);
	FILE *file_fd = NULL;
	if ((file_fd = fopen(AES_KF, "r")) == NULL) {
                perror("Aes_read_key::Error Opening AES txt file...\n");
                exit(EXIT_FAILURE);
        }

	fgets((char *) aes_key, BUFLEN, file_fd);
	aes_key[strlen((const char *)aes_key) - 1] = 0;
	return aes_key;
}


/*
 * retrieves an RSA key from the key file
 */
RSA *rsa_read_key(char *kfile) {

	RSA *rsa = NULL;
	FILE *ffd = fopen(kfile,"rb");
	if (!(ffd)){
		perror("Error in opening file.\n");
		return NULL;
	}

	rsa = RSA_new();

	if (strstr((const char *) kfile, "priv"))
		rsa = PEM_read_RSAPrivateKey(ffd, &rsa, NULL, NULL);
	else
		rsa = PEM_read_RSA_PUBKEY(ffd, &rsa, NULL, NULL);
	return rsa;
}


/*
 * encrypts the data with 128-bit AES CBC
 */
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext)
{

	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		perror("Error in CTX initiliazation!\n");
	}

	/* Start Encryption
	 	* 1. key length of key and cipher apropriate with cipher
        * 2. key has to be 128 bits ( 128 bit encryption)
	 	* 3. IV size must be same as the block size. (16)
	 */

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
		perror("Error in EVP encryption initiazation!\n");
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
   	 * EVP_EncryptUpdate can be called multiple times if necessary
   	 */

  	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
    		perror("Error in EVP encryption update!\n");
	}

  	ciphertext_len = len;

  	/* Finalise the encryption. Further ciphertext bytes may be written at
   	 * this stage.
   	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		perror("Error in EVP final step!\n");

	ciphertext_len += len;

  	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

/*
 * decrypts the data and returns the plaintext size
 */
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

  	if(!(ctx = EVP_CIPHER_CTX_new())){
		perror("Error in CTX initiliazation!\n");
	}

  	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
		perror("Error in Decryption initaliazation!\n");
	}

  	/* Provide the message to be decrypted, and obtain the plaintext output.
   	 * EVP_DecryptUpdate can be called multiple times if it is necessary
   	*/
  	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    		perror("Error In Decryption update!\n");
	}

	plaintext_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		perror("Error in Decryption final step!\n");
	}
	plaintext_len += len;

  	/* Clean up */
  	EVP_CIPHER_CTX_free(ctx);

  	return plaintext_len;
}


/*
 * Split blocks Encryption
 * If the messages are bigger than the key size and connot fit
 */
int rsa_split_encryption(unsigned char *plaintext, int plaintext_len, RSA *key, unsigned char *ciphertext, int phase)
{
	int tmp1 = 0, tmp2 = 0;
	int sub_length = 0, length = 0;
    int limit = RSA_size(key) - RSA_PKCS1_PADDING_SIZE;
	int blockno = plaintext_len / limit;
	int next = 0;
	int  cur = 0;
	int  cnt = 0;

	while (cnt <= blockno) {
		tmp1 = cnt * limit;
		tmp2 = cnt * (limit + RSA_PKCS1_PADDING_SIZE);

		next = plaintext_len - tmp1;
		if (next > limit)
			cur = limit;
		else
			cur = next;

		if (phase == 1)
			sub_length = RSA_public_encrypt (cur, plaintext + tmp1, ciphertext + tmp2, key, RSA_PKCS1_PADDING);
		else
			sub_length = RSA_private_encrypt(cur, plaintext + tmp1, ciphertext + tmp2, key, RSA_PKCS1_PADDING);
		length = length + sub_length;
		cnt++;
	}

	return length;
}

/*
 * Split blocks Decryption
 * If the messages are bigger than the key size and connot fit
 */

int rsa_split_decrypt(unsigned char *ciphertext, int ciphertext_len, RSA *key, unsigned char *plaintext, int phase)
{
	int tmp1 = 0, tmp2 = 0;
	int limit = RSA_size(key) - RSA_PKCS1_PADDING_SIZE;
	int cnt  = 0;
	int next = 0;
	int cur  = 0;
	int blockno = ciphertext_len / limit;
	int sub_length, length = 0;

	while (cnt <= blockno && next >= 0) {
		tmp1 = cnt * RSA_size(key);
		tmp2 = cnt * limit;
		next = ciphertext_len - length;

		if (next >= RSA_size(key))
			cur = RSA_size(key);
		else
			cur = next;

		if (phase == 0)
			sub_length = RSA_private_decrypt(cur, ciphertext + tmp1, plaintext + tmp2, key, RSA_PKCS1_PADDING);
		else
			sub_length =  RSA_public_decrypt(cur, ciphertext + tmp1, plaintext + tmp2, key, RSA_PKCS1_PADDING);
		length += sub_length;
		cnt ++;
	}

	return ++length;
}

/*
 * RSA public key encryption
 */
int rsa_pub_encrypt(unsigned char *plaintext, int plaintext_len, RSA *key, unsigned char *ciphertext)
{
	int len;
	int limit = RSA_size(key) - RSA_PKCS1_PADDING_SIZE;	/* 256 - 11 = 245 */

	if (plaintext_len > limit)
		len = rsa_split_encryption(plaintext, plaintext_len, key, ciphertext, 1);
	else
		len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, key, RSA_PKCS1_PADDING);

	if (len == -1)
		printf("Error in Public key Encryption!\n");

	return len;
}



/*
 * RSA private key decryption
 */
int rsa_prv_decrypt(unsigned char *ciphertext, int ciphertext_len, RSA *key, unsigned char *plaintext)
{
	int len;

	if (ciphertext_len > RSA_size(key))
		len = rsa_split_decrypt(ciphertext, ciphertext_len, key, plaintext, 0);
	else
		len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, key, RSA_PKCS1_PADDING);

	if(len <= -1)
		printf("Error in private key decryption\n");

	return len;
}


/*
 * RSA private key encryption
 */
int rsa_prv_encrypt(unsigned char *plaintext, int plaintext_len, RSA *key, unsigned char *ciphertext)
{
	int len = 0;

	if(plaintext_len > RSA_size(key))
		len = rsa_split_encryption(plaintext, plaintext_len, key, ciphertext, 0);
	else
		len = RSA_private_encrypt(plaintext_len, plaintext, ciphertext, key, RSA_PKCS1_PADDING);

	if(len == -1)
		printf("Error in Private Key Enrcyption!\n");

	return len;
}


/*
 * RSA public key decryption
 */
int rsa_pub_decrypt(unsigned char *ciphertext, int ciphertext_len, RSA *key, unsigned char *plaintext)
{
	int len;

	if(ciphertext_len > (RSA_size(key) - RSA_PKCS1_PADDING_SIZE))
		len = rsa_split_decrypt(ciphertext, ciphertext_len, key, plaintext, 1);
	else
		len = RSA_public_decrypt(ciphertext_len, ciphertext, plaintext, key, RSA_PKCS1_PADDING);

	if (len <= -1)
		printf("Error in Public Key decryption!\n");

	return len;
}

/*
 * RSA Public(Private) encryption
 */
int rsa_pub_priv_encrypt(unsigned char *plaintext, int plaintext_len, RSA *pub_k, RSA *priv_k, unsigned char *ciphertext)
{
	int len1 = 0, len2 = 0;

	/* temp buffer gia to 1o perasma. */
	unsigned char tmp[BUFLEN];
	bzero(tmp, BUFLEN);

	len1 = rsa_prv_encrypt(plaintext, plaintext_len, priv_k, tmp);
	if (len1 <= -1)
		perror("Error in First (Private) Encryption!\n");

	/* Second padding */
	len2 = rsa_pub_encrypt(tmp, len1, pub_k, ciphertext);
	if (len2 <= -1)
		perror("Error in Second (Public) Encryption!\n");

	return len2;
}


/*
 * RSA Public(Private) decryption
 */
int rsa_pub_priv_decrypt(unsigned char *ciphertext, int ciphertext_len, RSA *pub_k, RSA *priv_k, unsigned char *plaintext)
{
	int len1 = 0, len2 = 0;

	/* temp buffer gia to 1o perasma. */
	unsigned char tmp[BUFLEN];
	bzero(tmp, BUFLEN);

	len1 = rsa_prv_decrypt(ciphertext, ciphertext_len, priv_k, tmp);
	if (len1 <= -1)
		perror("Error in First (Private) Decryption!\n");
	/* Second padding */
	len2 = rsa_pub_decrypt(tmp, len1, pub_k, plaintext);
	if (len2 <= -1)
		perror("Error in Second (Public) DEcryption!\n");

	return len2;
}


/* EOF */
