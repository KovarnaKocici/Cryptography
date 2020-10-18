#include <iostream>

#include "rc4.h"
#include "gtest/gtest.h"

#define DEBUG 0

void printCorrect(uint8_t text[], uint32_t size) {
	#if DEBUG
	for (int i = 0; i < size; i++)
	{
		std::cout << text[i];
	}
	std::cout << "\n";
	#endif //DEBUG
}

TEST(RC4, Encrypt_Test) {
	RC4 rc4;
	unsigned char plain[] = { 'P','l','a','i','n','t','e','x','t' };
	unsigned char key[] = { 'K','e','y' };

	uint8_t* init = plain;
	printCorrect(init, sizeof plain);

	uint8_t* enc = new uint8_t[sizeof plain];
	uint8_t* dec = new uint8_t[sizeof plain];

	rc4.SetKey(key, sizeof key);
	rc4.Encrypt(plain, enc, sizeof plain);

	rc4.SetKey(key, sizeof key);
	rc4.Decrypt(enc, dec, sizeof plain);

	printCorrect(dec, sizeof plain);
	for (int i = 0; i < sizeof plain; i++)
	{
		EXPECT_EQ(init[i], dec[i]);
	}

	delete[] enc;
	delete[] dec;
}
