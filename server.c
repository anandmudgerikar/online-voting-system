#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <gmp.h>
#include "rsa_gmp.cpp"

#define MAXVOTE 4

private_key ku;
public_key kp;

private_key kus;
public_key kps;

pthread_t client_tid[MAXVOTE]; // Table that stores thread identifiers
int last; // Last available spot in client_tid[]

int response; // Number of response
int actual_vote; // Number of actual voter
mpz_t prime[MAXVOTE]; // Prime numbers
mpz_t returned_prime[MAXVOTE];
int pos;
sem_t mutex; // Semaphore
int mode; // Mode for clients in Mental Poker

mpz_t vote[MAXVOTE];
mpz_t id_perm[MAXVOTE];
mpz_t id_enc[MAXVOTE];
mpz_t vote_enc[MAXVOTE];
int place;

// Structure that stores client's socket, thread attribute and tid index in client_tid[]
struct client_conn {
	int client_sock;
	pthread_attr_t attr;
	int ind;
};

// Print client_tid[]
void printtable() {
	int i;
	for (i = 0; i < MAXVOTE; i++)
		printf("%ld ", client_tid[i]);
	printf("\n");
}

// Find next available spot in client_tid[]
int next_t() {
	int i = 0;
	while (client_tid[last] != 0 && i < MAXVOTE) {
		last = (last + 1) % MAXVOTE;
		i++;
	}
	if (i == MAXVOTE)
		return -1;
	return last;
}

// Initialize for scheme
void init() {
	int i;
	// Initialize public key
	mpz_init(kp.n);
	mpz_init(kp.e);

	// Initialize private key
	mpz_init(ku.n);
	mpz_init(ku.e);
	mpz_init(ku.d);
	mpz_init(ku.p);
	mpz_init(ku.q);

	// Initialize public key
	mpz_init(kps.n);
	mpz_init(kps.e);

	// Initialize private key
	mpz_init(kus.n);
	mpz_init(kus.e);
	mpz_init(kus.d);
	mpz_init(kus.p);
	mpz_init(kus.q);

	//mpz_set_ui(ku.p,3);

	int flag= 0;
	generate_keys(&ku, &kp,flag,ku.p,ku.q);

	generate_keys_server(&kus, &kps);

	/*printf("---------------Public Key-----------------\n");
	printf("kp.n is [%s]\n", mpz_get_str(NULL, 16, kps.n));
	printf("kp.e is [%s]\n", mpz_get_str(NULL, 16, kps.e));
	printf("---------------Private Key------------------\n");
	printf("ku.n is [%s]\n", mpz_get_str(NULL, 16, kus.n));
	printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, kus.e));
	printf("ku.d is [%s]\n", mpz_get_str(NULL, 16, kus.d));
	printf("ku.p is [%s]\n", mpz_get_str(NULL, 16, kus.p));
	printf("ku.q is [%s]\n", mpz_get_str(NULL, 16, kus.q));*/

	for (i = 0; i < MAXVOTE; i++) {
		mpz_init(vote[i]);
		mpz_init(id_perm[i]);
		mpz_init(vote_enc[i]);
		mpz_init(id_enc[i]);
	}
	place = 0;

	for (i = 0; i < MAXVOTE; i++) {
		client_tid[i] = 0;
		mpz_init(prime[i]);
		mpz_init(returned_prime[i]);
	}
	last = 0;

	response = 0;
	actual_vote = 0;
	pos = 0;
	sem_init(&mutex, 0, 1); // Initialize semaphore
	for (i = 0; i < MAXVOTE; i++) {
		mpz_set_ui(prime[i],i + 1);
		mpz_set_ui(returned_prime[i],0);
	}
	mode = 0;
}

void *client_handler (void *arg) {
	int i, j;

	struct client_conn *client_ptr = (struct client_conn *)arg;

	int msg_size;
	char client_msg[1000];
	memset(client_msg, 0, sizeof(client_msg));
	char reply[1000];
	memset(reply, 0, sizeof(client_msg));
	int count=0;

	// Ask client whether to vote
	send(client_ptr->client_sock, "##################################\n### Welcome to E-Voting System ###\n##################################\nDo you want to vote?\nYour response:  [Y/N]\0", 1000, 0);
	if (recv(client_ptr->client_sock, client_msg, sizeof(client_msg), 0) > 0) {
		printf("Name: %s decides to vote\n", client_msg);
		sem_wait(&mutex);
		response++;
		actual_vote++;
		sem_post(&mutex);
	}
	else {
		printf("Client quit voting.\n");
		sem_wait(&mutex);
		response++;
		sem_post(&mutex);
		client_tid[client_ptr->ind] = 0;
		close(client_ptr->client_sock);
		free(client_ptr);
		return NULL;
	}
	memset(client_msg, 0, sizeof(client_msg));

	// Client decide to vote
	sem_wait(&mutex);
	while (response < MAXVOTE) {
		sem_post(&mutex);
		usleep(200000);
		sem_wait(&mutex);
	}
	if (mode == 0) { // Need help from this client in Mental Poker
		mode = 1;
		sprintf(reply, "%d", MAXVOTE);
		send(client_ptr->client_sock, reply, sizeof(reply), 0); // Send MAXVOTE

		// Send p and q
		//printf("%s\n",mpz_get_str(reply,16,ku.p ));
		mpz_get_str(reply,16,ku.p );
		send(client_ptr->client_sock, reply, sizeof(reply), 0); // Send p

		//printf("%s\n",mpz_get_str(reply,16,ku.q));
		mpz_get_str(reply, 16, ku.q);
		send(client_ptr->client_sock, reply, sizeof(reply), 0); // Send q

		// Send primes
		for (i = 0; i < MAXVOTE; i++) {
			//printf("%s\n", mpz_get_str(reply, 16, prime[i]));
			mpz_get_str(reply, 16, prime[i]);
			send(client_ptr->client_sock, reply, sizeof(reply), 0); // Send p
		}

		// Get enciphered primes
		for (i = 0; i < MAXVOTE; i++) {
			recv(client_ptr->client_sock, client_msg, sizeof(client_msg), 0);
			mpz_set_str(returned_prime[i], client_msg, 16);
			memset(client_msg, 0, sizeof(client_msg));
			//printf("\n%s\n",mpz_get_str(NULL,16,returned_prime[i]));
		}

		// Shuffle primes
		srand(time(NULL));
		mpz_t temp;
		mpz_init(temp);
		for (i = 0; i < MAXVOTE; i++) {
			j = rand() % MAXVOTE;
			mpz_set(temp, returned_prime[i]);
			mpz_set(returned_prime[i], returned_prime[j]);
			mpz_set(returned_prime[j], temp);
		}

		// Send back a prime for this client
		//printf("%s\n", mpz_get_str(reply, 16, returned_prime[0]));
		mpz_get_str(reply, 16, returned_prime[0]);
		send(client_ptr->client_sock, reply, sizeof(reply), 0);
		response++;

		while (response != (MAXVOTE + actual_vote)) {
			sem_post(&mutex);
			usleep(500000);
			sem_wait(&mutex);
		}
		sprintf(reply, "%d", actual_vote);
		send(client_ptr->client_sock, reply, sizeof(reply), 0);
		for (i = 1; i < actual_vote; i++) {
			//printf("%s\n", mpz_get_str(reply, 16, returned_prime[i]));
			mpz_get_str(reply, 16, returned_prime[i]);
			send(client_ptr->client_sock, reply, sizeof(reply), 0);

			recv(client_ptr->client_sock, client_msg, sizeof(client_msg), 0);
			mpz_set_str(returned_prime[i],client_msg,16);
			memset(client_msg, 0, sizeof(client_msg));
			//printf("\n%s\n",mpz_get_str(NULL,16,returned_prime[i]));
		}
		response = 1;
		sem_post(&mutex);
	}
	else { // No need for help in MP
		sprintf(reply, "%d", 0);
		send(client_ptr->client_sock, reply, sizeof(reply), 0);
		
		/* Send p and q */
		//printf("%s\n", mpz_get_str(reply,16,ku.p ));
		mpz_get_str(reply, 16, ku.p);
		send(client_ptr->client_sock, reply, sizeof(reply), 0);

		//printf("%s\n",mpz_get_str(reply,16,ku.q));
		mpz_get_str(reply, 16, ku.q);
		send(client_ptr->client_sock, reply, sizeof(reply), 0);

		int k = ++pos;
		//printf("%s\n", mpz_get_str(reply, 16, returned_prime[k]));
		mpz_get_str(reply, 16, returned_prime[k]);
		send(client_ptr->client_sock, reply, sizeof(reply), 0);

		recv(client_ptr->client_sock, client_msg, sizeof(client_msg), 0);
		mpz_set_str(returned_prime[k],client_msg,16);
		memset(client_msg, 0, sizeof(client_msg));
		//printf("\n%s\n",mpz_get_str(NULL,16,returned_prime[k]));

		response++;
		
		while (response != 1) {
			sem_post(&mutex);
			usleep(500000);
			sem_wait(&mutex);
		}
		//printf("%s\n", mpz_get_str(reply, 16, returned_prime[k]));
		mpz_get_str(reply, 16, returned_prime[k]);
		send(client_ptr->client_sock, reply, sizeof(reply), 0);
		sem_post(&mutex);
	}

	//printf("%s\n", mpz_get_str(reply, 16, kus.n));
	mpz_get_str(reply, 16, kus.n);
	send(client_ptr->client_sock, reply, sizeof(reply), 0); // Send server's N to clients

	mpz_t temp;
	mpz_init(temp);
	mpz_t temp1;
	mpz_init(temp1);

	// Receive votes from clients
	while ((msg_size = recv(client_ptr->client_sock, client_msg, sizeof(client_msg), 0)) > 0) {
		mpz_set_str(temp, client_msg, 16);
		memset(client_msg, 0, sizeof(client_msg));
		//printf("\n%s\n",mpz_get_str(NULL,16,temp));
		block_decrypt(temp1, temp, kus);
		mpz_set(temp, temp1);
		//printf("Vote is: %s \n", mpz_get_str(NULL, 16, temp));

		mpz_t id;
		mpz_init(id);
		mpz_t temp3;
		mpz_init(temp3);

		recv(client_ptr->client_sock, client_msg, sizeof(client_msg), 0);
		mpz_set_str(id, client_msg, 16);
		memset(client_msg, 0, sizeof(client_msg));
		//printf("\n%s\n",mpz_get_str(NULL,16,id));
		block_decrypt(temp1, id, kus);
		mpz_set(temp3, id);
		mpz_set(id, temp1);
		//printf("identifier is: %s\n", mpz_get_str(NULL, 16, id));

		int t = 100;
		for (i = 0; i < MAXVOTE; i++) {
			if(mpz_cmp(id_perm[i], id) == 0)
			{
				mpz_set(vote[i], temp);
				break;
			}
			else if (mpz_cmp_ui(id_perm[i],0) == 0) {
				t = i;
			}

		}

		if (i == MAXVOTE) {
			mpz_set(id_perm[t], id);
			mpz_set(vote[t], temp);
			mpz_set(id_enc[t], temp3);
		}

		printf("\n******************************************************************\n");
		printf("Final Result:\n");
		for (i = 0; i < MAXVOTE; i++) {
			printf("id: %s\tvote: %s\n",mpz_get_str(NULL,16,id_enc[i]), mpz_get_str(NULL,16,vote[i]));
		}
		printf("******************************************************************\n");



	}

	if (msg_size == 0) {
		puts("Client disconnected.\n");
		fflush(stdout);
	}
	else if (msg_size == -1) {
		perror("recv failed.\n");
	}

	client_tid[client_ptr->ind] = 0;
	close(client_ptr->client_sock);
	free(client_ptr);
	return NULL;
}

int main(int argc, char* argv[]) {
	int server_sock, c;
	struct client_conn *client_ptr;
	struct sockaddr_in server, client;

	init();

	//Create socket
	server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // 0
	if (server_sock == -1) {
		printf("Could not create socket.\n");
	}
	puts("Socket created.\n");

	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(8880);

	//Bind
	if (bind(server_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("bind failed.\n");
		return 1;
	}
	puts("bind done.\n");

	//Listen
	listen(server_sock, SOMAXCONN); //default: SOMAXCONN

	//Accept an incoming connection
	puts("Waiting for incoming connections...\n");
	c = sizeof(struct sockaddr_in);

	/********************************************************/
	/***************** Start Voting Scheme ******************/
	/********************************************************/

	//Accept connection from an incoming client
	while (1) {	//while in a given time
		client_ptr = (struct client_conn*)malloc(sizeof(struct client_conn));
		client_ptr->ind = 0;
		pthread_attr_init(&client_ptr->attr);
		pthread_attr_setdetachstate(&client_ptr->attr, PTHREAD_CREATE_DETACHED);
		client_ptr->client_sock = accept(server_sock, (struct sockaddr *)&client, (socklen_t *)&c);
		if (client_ptr->client_sock < 0) {
			perror("accept client failed.\n");
			free(client_ptr);
			continue;
		}

		int i = next_t();
		if (i == -1) {
			perror("Max clients. No more.\n");
			close(client_ptr->client_sock);
			free(client_ptr);
		}
		else {
			puts("Connection accepted.");

			client_ptr->ind = i;
			if (pthread_create(&client_tid[i], &client_ptr->attr, client_handler, (void *)client_ptr) != 0) {
				perror("Can't create new thread.\n");
				client_tid[i] = 0;
				close(client_ptr->client_sock);
				free(client_ptr);
			}
		}
	}
	
	close(server_sock);

	return 0;
}
