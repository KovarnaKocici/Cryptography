#include "rsa-helpers.h"

bool millerRabin_isPrimeCheck(mpz_t value) {

	if (mpz_even_p(value) == 1)
		return true;

	mpz_t tempValue;
	mpz_init(tempValue);
	mpz_sub_ui(tempValue, value, (unsigned int)1);

	mpz_t tempStore;
	mpz_init(tempStore);
	mpz_set(tempStore, tempValue);

	unsigned int a = 0;

	// Finding out the value for r which is (value / 2^d)
	while (true) {
		if (mpz_even_p(tempValue) == 0) {
			break;
		}
		a++;
		mpz_cdiv_q_ui(tempValue, tempValue, (unsigned int)2);
	}

	// Doing the check for 64 rounds
	for (size_t i = 0; i < rounds; i++) {
		if (millerTest(tempValue, tempStore, value, a) == false)
			return false;
	}
	return true;
};

bool millerTest(mpz_t m, mpz_t tempStore, mpz_t value, unsigned int a) {

	mpz_t pickRandA;
	mpz_init(pickRandA);

	mpz_t storeX;
	mpz_init(storeX);

	// Picking up a random value between 0 and value-2
	mpz_urandomm(pickRandA, rand, tempStore);

	// Computing pickRandA ^ m mod given value
	mpz_powm(storeX, pickRandA, m, value);

	// Check whether the it is equal to 0 or (value-1)
	if (mpz_cmp_ui(value, (unsigned int)1) == 0 || mpz_cmp(value, tempStore) == 0)
	{
		return true;
	}

	for (size_t j = 0; j < a - 1; j++) {
		mpz_powm_ui(storeX, storeX, (unsigned long int)2, value);
		if (mpz_cmp_ui(storeX, (unsigned int)1) == 0) {
			// Not a prime, hence return false
			return false;
		}
		if (mpz_cmp(storeX, tempStore) == 0)
			return true;
	}
	return false;
};