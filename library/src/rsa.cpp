#include "rsa.h"
#include "rsa-helpers.h"
#include "OAEP.h"
#include <iostream>
#include <math.h>
#include <time.h>

RSA::RSA() {
		seed = 1;
		mpz_init(rsaP);
		mpz_init(rsaQ);
		mpz_init(n);
		mpz_init(phi);
		mpz_init(rsaE);
		mpz_init(rsaD);
		mpz_init(message);
		mpz_init(ciphertext);
		mpz_init(plaintext);
		mpz_init(one);
		mpz_set_str(one, "1", 10);
		gmp_randinit_default(rand);
		gmp_randseed_ui(rand, seed);
}

void RSA::generateLargePrimeNumbers() {

	bool isPrimeFlag = false;

	// get a random integer which has bits of length BITS using mpz_urandomb method
	mpz_urandomb(rsaP, rand, BITS);
	isPrimeFlag = millerRabin_isPrimeCheck(rsaP);
	while (!isPrimeFlag)
	{
		mpz_nextprime(rsaP, rsaP);
		isPrimeFlag = millerRabin_isPrimeCheck(rsaP);
	}

	isPrimeFlag = false;
	// get a random integer which has bits of length BITS using mpz_urandomb method
	mpz_urandomb(rsaQ, rand, BITS);
	isPrimeFlag = millerRabin_isPrimeCheck(rsaQ);
	while (!isPrimeFlag)
	{
		mpz_nextprime(rsaQ, rsaQ);
		isPrimeFlag = millerRabin_isPrimeCheck(rsaQ);
	}

	// Calculate RSA modulus n and phi values
	mpz_mul(n, rsaP, rsaQ);
	mpz_t tempP;
	mpz_t tempQ;

	mpz_init(tempP);
	mpz_init(tempQ);

	mpz_sub(tempP, rsaP, one);
	mpz_sub(tempQ, rsaQ, one);

	mpz_mul(phi, tempP, tempQ);

	gmp_printf("chosen rsaP value: %Zd\n", rsaP);
	cout << "\n";
	gmp_printf("chosen rsaQ value: %Zd\n", rsaQ);
	cout << "\n";
	gmp_printf("RSA modulus n value: %Zd\n", n);

	cout << "\n";
	gmp_printf("RSA Phi value: %Zd\n", phi);
	cout << "\n";

}

void RSA::calculatePublicPrivateKeys() {
	//		unsigned long int coPrime = 65537;
	mpz_t gcdValue;
	mpz_init(gcdValue);

	mpz_t coPrime;
	mpz_init(coPrime);

	mpz_urandomb(coPrime, rand, BITS);

	while (true)
	{
		mpz_gcd(gcdValue, phi, coPrime);
		if (mpz_cmp_ui(gcdValue, (unsigned long int)1) == 0)
			break;
		mpz_nextprime(coPrime, coPrime);
	}

	mpz_set(rsaE, coPrime);
	mpz_invert(rsaD, rsaE, phi);

	gmp_printf("chosen E value: %Zd\n", rsaE);
	cout << "\n";
	gmp_printf("chosen D value: %Zd\n", rsaD);
	cout << "\n";
}

void RSA::Encrypt() 
{
	mpz_powm(ciphertext, message, rsaE, n);
	cout << "\n\nCipher Text: " << ciphertext << endl;
}

void RSA::Decrypt() {
	mpz_powm(plaintext, ciphertext, rsaD, n);
	cout << "\nDecrypted Text:" << plaintext << endl;
}

~RSA::RSA() {
	mpz_clear(rsaP);
	mpz_clear(rsaQ);
	mpz_clear(n);
	mpz_clear(phi);
	mpz_clear(rsaE);
	mpz_clear(rsaD);
	mpz_clear(message);
	mpz_clear(ciphertext);
}