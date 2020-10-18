#ifndef SALSA20_LIBRARY_INCLUDE_SALSA20_H_
#define SALSA20_LIBRARY_INCLUDE_SALSA20_H_

class Salsa20{
public:
	static const int IV_LENGTH = 8;
	static const int KEY_LENGTH = 32;

	Salsa20(const uint8_t key[], const uint8_t iv[]);

	void keySetup(const uint8_t key[]);

	void ivSetup(const uint8_t iv[IV_LENGTH]);

	void encrypt(uint8_t m[], const uint32_t bytes);

	void decrypt(uint8_t m[], const uint32_t bytes);

private:
	void wordToByte(uint32_t input[16]);

	uint32_t m_state[16];
	uint8_t  m_output[64];
};

#endif //RC4_LIBRARY_INCLUDE_RC4_H_