#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <time.h>
#include "rsa_gmp.cpp"

int main( int argc, char* argv[]) {
	int sock;
	struct sockaddr_in server;
	char message[1000], server_reply[1000];
	int n;
	mpz_t identifier;
	mpz_init(identifier);
	mpz_t temp;
	mpz_init(temp);
	public_key kps;

	mpz_t p_perm;
	mpz_t q_perm;

	private_key ku;
	public_key kp;

	// Initialize public key
	mpz_init(kp.n);
	mpz_init(kp.e);

	// Initialize public key
	mpz_init(kps.n);
	mpz_init(kps.e);
	mpz_set_ui(kps.e, 3);

	// Initialize private key
	mpz_init(ku.n);
	mpz_init(ku.e);
	mpz_init(ku.d);
	mpz_init(ku.p);
	mpz_init(ku.q);

	mpz_init(p_perm);
	mpz_init(q_perm);

	//Create socket
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == -1) {
		printf("Could not create socket.\n");
		return -1;
	}
	//setblocking(sock);
	puts("Socket created.\n");

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(8880);

	//Connect to remote server
	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("Connect failed.\n");
		return -1;
	}
	puts("Connected.\n");

	/********************************************************/
	/***************** Start Voting Scheme ******************/
	/********************************************************/

	// Decide to vote or not
	recv(sock, server_reply, sizeof(server_reply), 0);
	printf("%s\n", server_reply);
	scanf("%s", message);
	while (strcmp(message, "Y") != 0 && strcmp(message, "N") != 0) { // Invalid answer
		printf("Re-enter your decision. [Y/N] only:\t");
		memset(message, 0, sizeof(message));
		scanf("%s", message);
	}
	if (strcmp(message, "N") == 0) { // If client dicides not to vote, quit
		printf("Thank you for your participation. System will quit now.\n");
		close(sock);
		return 0;
	}
	else { // If client decides to vote, send client's name to server
		printf("Please enter your name: ");
		scanf("%s", message);
		while (strlen(message) == 0) {
			printf("Please re-enter your name: ");
			scanf("%s", message);
		}
		if (send(sock, message, sizeof(message), 0) <= 0) {
			puts("Send name failed");
			close(sock);
			return -1;
		}
	}

	// Initialize and distribute prime identifiers using Mental Poker
	recv(sock, server_reply, sizeof(server_reply), 0);
	n = atoi(server_reply);

	if (n > 0) { // This client needs to help in MP
		// Receive p and q
		recv(sock, server_reply, sizeof(server_reply), 0);
		mpz_set_str(p_perm, server_reply, 16);
		memset(server_reply, 0, sizeof(server_reply));
		//printf("\n%s\n",mpz_get_str(NULL,16,p_perm));

		recv(sock, server_reply, sizeof(server_reply), 0);
		mpz_set_str(q_perm,server_reply,16);
		memset(server_reply, 0, sizeof(server_reply));
		//printf("\n%s\n",mpz_get_str(NULL,16,q_perm));

		//generate e and d
		int flag= 1;
		generate_keys(&ku, &kp,flag,p_perm,q_perm);

		/*printf("---------------Public Key-----------------\n");
		printf("kp.n is [%s]\n", mpz_get_str(NULL, 16, kp.n));
		printf("kp.e is [%s]\n", mpz_get_str(NULL, 16, kp.e));
		printf("---------------Private Key------------------\n");
		printf("ku.n is [%s]\n", mpz_get_str(NULL, 16, ku.n));
		printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, ku.e));
		printf("ku.d is [%s]\n", mpz_get_str(NULL, 16, ku.d));
		printf("ku.p is [%s]\n", mpz_get_str(NULL, 16, ku.p));
		printf("ku.q is [%s]\n", mpz_get_str(NULL, 16, ku.q));*/

		int i, j;
		mpz_t prime[n];
		for (i = 0; i < n; i++) {
			mpz_init(prime[i]);
		}
		for (i = 0; i < n; i++) { // Receive primes sent by server
			recv(sock, server_reply, sizeof(server_reply), 0);
			mpz_set_str(prime[i],server_reply,16);
			memset(server_reply, 0, sizeof(server_reply));
			//printf("\n%s\n",mpz_get_str(NULL,16,prime[i]));

			//encrypt the data
			block_encrypt(temp, prime[i], kp);
			mpz_set(prime[i],temp);
			//printf("encrypted is [%s]\n", mpz_get_str(NULL, 16, prime[i]));
		}

		// Shuffle encrypted primes and send them back to server
		srand(time(NULL));
		for (i = 0; i < n; i++) {
			j = rand() % n;
			mpz_set(temp, prime[i]);
			mpz_set(prime[i], prime[j]);
			mpz_set(prime[j], temp);
		}
		
		// Send them back
		for (i = 0; i < n; i++) {
			//printf("%s\n", mpz_get_str(message, 16, prime[i]));
			mpz_get_str(message, 16, prime[i]);
			send(sock, message, sizeof(message), 0);
		}
		
		// Receive prime identifier, decryption needed
		recv(sock, server_reply, sizeof(server_reply), 0);
		mpz_set_str(identifier, server_reply, 16);
		memset(server_reply, 0, sizeof(server_reply));

		/* Decrypt identifier for self-use */
		block_decrypt(temp, identifier, ku);
		mpz_set(identifier,temp);
		printf("\nMy identifier: %s\n", mpz_get_str(NULL, 16, identifier));

		// Receive actual number of voter
		recv(sock, server_reply, sizeof(server_reply), 0);
		n = atoi(server_reply);
		memset(server_reply, 0, sizeof(server_reply));

		for (i = 0; i < (n - 1); i++) {
			recv(sock, server_reply, sizeof(server_reply), 0);
			mpz_set_str(temp, server_reply, 16);
			memset(server_reply, 0, sizeof(server_reply));
			//printf("\n%s\n",mpz_get_str(NULL,16, temp));

			mpz_t temp1;
			mpz_init(temp1);
			block_decrypt(temp1, temp, ku);
			mpz_set(temp,temp1);
			//printf("decrypted is [%s]\n", mpz_get_str(NULL, 16, temp));

			//printf("%s\n", mpz_get_str(message, 16, temp));
			mpz_get_str(message, 16, temp);
			send(sock, message, sizeof(message), 0);
			memset(server_reply, 0, sizeof(server_reply));
		}
	}
	else { // No need to help in MP
		// receive p q
		recv(sock, server_reply, sizeof(server_reply), 0);
		mpz_set_str(p_perm,server_reply,16);
		memset(server_reply, 0, sizeof(server_reply));
		//printf("\n%s\n",mpz_get_str(NULL,16,p_perm));

		recv(sock, server_reply, sizeof(server_reply), 0);
		mpz_set_str(q_perm,server_reply,16);
		memset(server_reply, 0, sizeof(server_reply));
		//printf("\n%s\n",mpz_get_str(NULL,16,q_perm));

		//generate e d
		int flag= 1;
		generate_keys(&ku, &kp,flag,p_perm,q_perm);

		/*printf("---------------Public Key-----------------\n");
		printf("kp.n is [%s]\n", mpz_get_str(NULL, 16, kp.n));
		printf("kp.e is [%s]\n", mpz_get_str(NULL, 16, kp.e));
		printf("---------------Private Key------------------\n");
		printf("ku.n is [%s]\n", mpz_get_str(NULL, 16, ku.n));
		printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, ku.e));
		printf("ku.d is [%s]\n", mpz_get_str(NULL, 16, ku.d));
		printf("ku.p is [%s]\n", mpz_get_str(NULL, 16, ku.p));
		printf("ku.q is [%s]\n", mpz_get_str(NULL, 16, ku.q));*/

		memset(server_reply, 0, sizeof(server_reply));
		recv(sock, server_reply, sizeof(server_reply), 0);
		mpz_set_str(temp, server_reply, 16);
		memset(server_reply, 0, sizeof(server_reply));
		//printf("\n%s\n",mpz_get_str(NULL,16, temp));

		/* Encipher received number using own encipher scheme */
		mpz_t temp1;
		mpz_init(temp1);
		block_encrypt(temp1, temp, kp);
		mpz_set(temp,temp1);
		//printf("encrypted is [%s]\n", mpz_get_str(NULL, 16, temp));

		//printf("%s\n", mpz_get_str(message, 16, temp));
		mpz_get_str(message, 16, temp);
		send(sock, message, sizeof(message), 0);
		memset(server_reply, 0, sizeof(server_reply));

		recv(sock, server_reply, sizeof(server_reply), 0);
		mpz_set_str(identifier, server_reply, 16);
		memset(server_reply, 0, sizeof(server_reply));
		//printf("\n%s\n",mpz_get_str(NULL,16, identifier));

		// Decrypt identifier for self-use
		mpz_init(temp1);
		block_decrypt(temp1, identifier, ku);
		mpz_set(identifier,temp1);
		printf("My identifier: %s \n", mpz_get_str(NULL, 16, identifier));

	}

	recv(sock, server_reply, sizeof(server_reply), 0);
	mpz_set_str(kps.n, server_reply, 16);
	memset(server_reply, 0, sizeof(server_reply));
	mpz_set_ui(kps.e,3);
	//printf("\n%s\n",mpz_get_str(NULL,16, kps.n));

	//keep communicating with server
	while(1) {
		char vote[10];
		printf("\nEnter you vote: [1 or 2] ");
		scanf("%s",vote);
		while (strcmp(vote, "1") != 0 && strcmp(vote, "2") != 0) {
			printf("Please re-enter your vote. [1 or 2] only: ");
			scanf("%s",vote);
		}

		mpz_t temp1;
		mpz_init(temp1);
		mpz_init(temp);
		mpz_set_str(temp,vote,16);
		block_encrypt(temp1,temp, kps);
		mpz_set(temp,temp1);
		printf("encrypted vote is [%s]\n", mpz_get_str(NULL, 16, temp));
		//printf("%s\n", mpz_get_str(message, 16, temp));
		mpz_get_str(message, 16, temp);
		send(sock, message, sizeof(message), 0);

		block_encrypt(temp1, identifier, kps);
		mpz_set(temp,temp1);
		printf("encrypted identifier is [%s]\n", mpz_get_str(NULL, 16, temp));
		//printf("%s\n", mpz_get_str(message, 16, temp));
		mpz_get_str(message, 16, temp);
		send(sock, message, sizeof(message), 0);

	}
	close(sock);
	return 0;
}
