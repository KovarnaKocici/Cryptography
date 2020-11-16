#ifndef IS_LIBRARY_INCLUDE_RSA_H_
#define IS_LIBRARY_INCLUDE_RSA_H_

#include<gmp.h>
#include<gmpxx.h>

const int BITS = 1024;
const int rounds = 64;

class RSA {
	mpz_t rsaP;
	mpz_t rsaQ;
	mpz_t n;
	mpz_t phi;
	mpz_t rsaE;
	mpz_t rsaD;
	mpz_t one;

public:
	mpz_t message;
	mpz_t ciphertext;
	mpz_t plaintext;

	gmp_randstate_t rand;
	unsigned long int seed;

public:
	RSA();
	// Miller-Rabin Primality Testing to find whether
	//a randomly chosen odd number is a prime number or not
	bool millerRabin_isPrimeCheck(mpz_t value);
	void generateLargePrimeNumbers();
	void calculatePublicPrivateKeys();
	void Encrypt();
	void Decrypt();

private:
	bool millerTest(mpz_t m, mpz_t tempStore, mpz_t value, unsigned int a);
};

#endif //IS_LIBRARY_INCLUDE_RSA_H_