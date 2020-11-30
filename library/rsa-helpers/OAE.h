#ifndef IS_LIBRARY_RSA_OAE_H_
#define IS_LIBRARY_RSA_OAE_H_

#include <iostream>
#include <stdio.h>
#include "gmp.h"
#include <openssl/sha.h>
#include <string.h>
#include <cstdlib>
#include <math.h>

using namespace std;

const int modulus_n = 256;
const int hlen = 32;

class OAEP
{

	int messageLen;
	int messageLabelLen;
	char lHash[hlen + 1];
	int dbLen = modulus_n - hlen - 1;

public:

	void os2ip(unsigned char octetString[], mpz_t result);
	unsigned char* i2osp(mpz_t integerValue, int xLen);
	unsigned char* getEncodedMessage(char message[], char messageLabel[]);
	unsigned char* getDecodedMessage(unsigned char encodedMessage[], char messageLabel[]);
private:
	void maskGenerationFunction(int ceilValue, int len, unsigned char input[], unsigned char output[]);
};

#endif //IS_LIBRARY_RSA_OAE_H_
