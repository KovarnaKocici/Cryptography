#include <gmpxx.h>

#ifndef IS_LIBRARY_RSA_HELPERS_H_
#define IS_LIBRARY_RSA_HELPERS_H_

static bool millerRabin_isPrimeCheck(mpz_t value);
static bool millerTest(mpz_t m, mpz_t tempStore, mpz_t value, unsigned int a);

#endif //IS_LIBRARY_RSA_HELPERS_H_