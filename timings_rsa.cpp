//============================================================================
// Name        : rsa_gmp.cpp
// Author      : 
// Version     :
// Copyright   : Would like to give props to gilgad13 whos code really helped us out
// Description : in C++, Ansi-style
//============================================================================

//just some imports
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

//defining block sizes and n= key size
#define MODULUS_SIZE 1024 /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE/8) /* This is the size of a block that gets en/decrypted at once */
#define BUFFER_SIZE ((MODULUS_SIZE/8) / 2) /* This is the number of bytes in n and p */

//define structures here
typedef struct {
mpz_t n; /* Modulus */
mpz_t e; /* Public Exponent */
} public_key;

typedef struct {
mpz_t n; /* Modulus */
mpz_t e; /* Public Exponent */
mpz_t d; /* Private Exponent */
mpz_t p; /* Starting prime p */
mpz_t q; /* Starting prime q */
} private_key;




void print_hex(char* arr, int len)
{
int i;
for(i = 0; i < len; i++)
printf("%02x", (unsigned char) arr[i]);
}

/* NOTE: Assumes mpz_t's are initted in ku and kp */
void generate_keys(private_key* ku, public_key* kp,int flag,mpz_t p_perm,mpz_t q_perm)
{
char buf[BUFFER_SIZE];
int i;
mpz_t phi; mpz_init(phi);
mpz_t tmp1; mpz_init(tmp1);
mpz_t tmp2; mpz_init(tmp2);
srand(time(NULL));

//we use a random public key e

mpz_set_ui(ku->e, 3);

if(flag==0)
{
/* Select p and q */
/* Start with p */
// Set the bits of tmp randomly
for(i = 0; i < BUFFER_SIZE; i++)
buf[i] = rand() % 0xFF;
// Set the top two bits to 1 to ensure int(tmp) is relatively large
buf[0] |= 0xC0;
// Set the bottom bit to 1 to ensure int(tmp) is odd (better for finding primes)
buf[BUFFER_SIZE - 1] |= 0x01;
// Interpret this char buffer as an int
mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(buf[0]), 0, 0, buf);
// Pick the next prime starting from that random number
mpz_nextprime(ku->p, tmp1);
/* Make sure this is a good choice*/
mpz_mod(tmp2, ku->p, ku->e); /* If p mod e == 1, gcd(phi, e) != 1 */

while(!mpz_cmp_ui(tmp2, 1))
{
mpz_nextprime(ku->p, ku->p); /* so choose the next prime */
mpz_mod(tmp2, ku->p, ku->e);
}

/* Now select q */
do {
for(i = 0; i < BUFFER_SIZE; i++)
buf[i] = rand() % 0xFF;
// Set the top two bits to 1 to ensure int(tmp) is relatively large
buf[0] |= 0xC0;
// Set the bottom bit to 1 to ensure int(tmp) is odd
buf[BUFFER_SIZE - 1] |= 0x01;
// Interpret this char buffer as an int
mpz_import(tmp1, (BUFFER_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
// Pick the next prime starting from that random number
mpz_nextprime(ku->q, tmp1);
mpz_mod(tmp2, ku->q, ku->e);

while(!mpz_cmp_ui(tmp2, 1))
{
mpz_nextprime(ku->q, ku->q);
mpz_mod(tmp2, ku->q, ku->e);
}
} while(mpz_cmp(ku->p, ku->q) == 0); /* If we have identical primes (unlikely), try again */
}

else
{
	mpz_set(ku->p, p_perm);
	mpz_set(ku->q, q_perm);


/* Calculate n = p x q */
mpz_mul(ku->n, ku->p, ku->q);
/* Compute phi(n) = (p-1)(q-1) */
mpz_sub_ui(tmp1, ku->p, 1);
mpz_sub_ui(tmp2, ku->q, 1);
mpz_mul(phi, tmp1, tmp2);

/* Calculate d (multiplicative inverse of e mod phi) */
if(mpz_invert(ku->d, ku->e, phi) == 0)
{
mpz_gcd(tmp1, ku->e, phi);
printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
printf("Invert failed\n");
}

/* Set public key */
mpz_set(kp->e, ku->e);
mpz_set(kp->n, ku->n);
}
return;
}

void generate_keys_orig(private_key* ku, public_key* kp)
{
char buf[BUFFER_SIZE];
int i;
mpz_t phi; mpz_init(phi);
mpz_t tmp1; mpz_init(tmp1);
mpz_t tmp2; mpz_init(tmp2);
srand(time(NULL));

//we use a random public key e

mpz_set_ui(ku->e, 3);


{
/* Select p and q */
/* Start with p */
// Set the bits of tmp randomly
for(i = 0; i < BUFFER_SIZE; i++)
buf[i] = rand() % 0xFF;
// Set the top two bits to 1 to ensure int(tmp) is relatively large
buf[0] |= 0xC0;
// Set the bottom bit to 1 to ensure int(tmp) is odd (better for finding primes)
buf[BUFFER_SIZE - 1] |= 0x01;
// Interpret this char buffer as an int
mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(buf[0]), 0, 0, buf);
// Pick the next prime starting from that random number
mpz_nextprime(ku->p, tmp1);
/* Make sure this is a good choice*/
mpz_mod(tmp2, ku->p, ku->e); /* If p mod e == 1, gcd(phi, e) != 1 */

while(!mpz_cmp_ui(tmp2, 1))
{
mpz_nextprime(ku->p, ku->p); /* so choose the next prime */
mpz_mod(tmp2, ku->p, ku->e);
}

/* Now select q */
do {
for(i = 0; i < BUFFER_SIZE; i++)
buf[i] = rand() % 0xFF;
// Set the top two bits to 1 to ensure int(tmp) is relatively large
buf[0] |= 0xC0;
// Set the bottom bit to 1 to ensure int(tmp) is odd
buf[BUFFER_SIZE - 1] |= 0x01;
// Interpret this char buffer as an int
mpz_import(tmp1, (BUFFER_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
// Pick the next prime starting from that random number
mpz_nextprime(ku->q, tmp1);
mpz_mod(tmp2, ku->q, ku->e);

while(!mpz_cmp_ui(tmp2, 1))
{
mpz_nextprime(ku->q, ku->q);
mpz_mod(tmp2, ku->q, ku->e);
}
} while(mpz_cmp(ku->p, ku->q) == 0); /* If we have identical primes (unlikely), try again */
}


{

/* Calculate n = p x q */
mpz_mul(ku->n, ku->p, ku->q);
/* Compute phi(n) = (p-1)(q-1) */
mpz_sub_ui(tmp1, ku->p, 1);
mpz_sub_ui(tmp2, ku->q, 1);
mpz_mul(phi, tmp1, tmp2);

/* Calculate d (multiplicative inverse of e mod phi) */
if(mpz_invert(ku->d, ku->e, phi) == 0)
{
mpz_gcd(tmp1, ku->e, phi);
printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
printf("Invert failed\n");
}

/* Set public key */
mpz_set(kp->e, ku->e);
mpz_set(kp->n, ku->n);
}
return;
}

void block_encrypt(mpz_t C, mpz_t M, public_key kp)
{
/* C = M^e mod n */
mpz_powm(C, M, kp.e, kp.n);

}

void block_decrypt(mpz_t M, mpz_t C, private_key ku)
{
mpz_powm(M, C, ku.d, ku.n);

}

int main()
{
int i;

mpz_t M; mpz_init(M);
mpz_t C; mpz_init(C);
mpz_t DC; mpz_init(DC);
private_key ku;
public_key kp;

// Initialize public key
mpz_init(kp.n);
mpz_init(kp.e);

// Initialize private key
mpz_init(ku.n);
mpz_init(ku.e);
mpz_init(ku.d);
mpz_init(ku.p);
mpz_init(ku.q);
clock_t start = clock ();
for(int i=0;i<100;i++)
generate_keys_orig(&ku, &kp);
double timeElapsed = double(( clock() - start )/ CLOCKS_PER_SEC);
printf("\ntime for key generation: %0.6lf\n",timeElapsed);

printf("---------------Private Key-----------------");
printf("kp.n is [%s]\n", mpz_get_str(NULL, 16, kp.n));
printf("kp.e is [%s]\n", mpz_get_str(NULL, 16, kp.e));
printf("---------------Public Key------------------");
printf("ku.n is [%s]\n", mpz_get_str(NULL, 16, ku.n));
printf("ku.e is [%s]\n", mpz_get_str(NULL, 16, ku.e));
printf("ku.d is [%s]\n", mpz_get_str(NULL, 16, ku.d));
printf("ku.p is [%s]\n", mpz_get_str(NULL, 16, ku.p));
printf("ku.q is [%s]\n", mpz_get_str(NULL, 16, ku.q));

char buf[6*BLOCK_SIZE];
for(i = 0; i < 6*BLOCK_SIZE; i++)
buf[i] = rand() % 0xFF;

mpz_import(M, (6*BLOCK_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
mpz_set_ui(M,34);
printf("original is [%s]\n", mpz_get_str(NULL, 16, M));

start = clock ();
for(int i=0;i<1000000;i++)
block_encrypt(C, M, kp);
printf("encrypted is [%s]\n", mpz_get_str(NULL, 16, C));
timeElapsed = double(( clock() - start )/ CLOCKS_PER_SEC);
printf("\ntime for key generation: %0.6lf\n",timeElapsed);

start = clock ();
for(int i=0;i<1000;i++)
block_decrypt(DC, C, ku);
printf("decrypted is [%s]\n", mpz_get_str(NULL, 16, DC));
timeElapsed = double(( clock() - start )/ CLOCKS_PER_SEC);
printf("\ntime for key generation: %0.6lf\n",timeElapsed);
return 0;
}
