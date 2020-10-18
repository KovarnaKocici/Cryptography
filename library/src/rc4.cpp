#include <stdexcept>

#include "rc4.h"

RC4::RC4() {
}

void RC4::SetKey(uint8_t key[], uint32_t keyLen) {
	if (1 <= keyLen && keyLen <= 256)
	{
		sizeKey = keyLen;

		prgaIndexA = 0;
		prgaIndexB = 0;
		for (int i = 0; i < 256; i++) {
			sbox[i] = i;
		}

		KSA(key);
	}
	else
		throw std::invalid_argument("Incorrect key length");
}

void RC4::Encrypt(uint8_t plainText[], uint8_t cipherText[], uint32_t Len) {
	PRGA(plainText, cipherText, Len);
}

void RC4::KSA(uint8_t* key)
{
	uint32_t j = 0;
	for (uint32_t i = 0; i < 256; i++) {
		j = (j + sbox[i] + key[i % sizeKey]) % 256;
		Swap(sbox, i, j);
	}
}

void RC4::Swap(uint8_t data[], uint32_t i, uint32_t j)
{
	uint8_t temp = data[i];
	data[i] = data[j];
	data[j] = temp;
}

void RC4::PRGA(uint8_t plainText[], uint8_t cipherText[], uint32_t Len)
{
	for (uint32_t k = 0; k < Len; k++) {
		prgaIndexA = (prgaIndexA + 1) % 256;
		prgaIndexB = (prgaIndexB + sbox[prgaIndexA]) % 256;
		Swap(sbox, prgaIndexA, prgaIndexB);
		cipherText[k] = sbox[(sbox[prgaIndexA] + sbox[prgaIndexB]) % 256] ^ plainText[k];
	}
}