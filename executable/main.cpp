#include <iostream>
#include <sstream>
#include <numeric>
#include <random>
#include <fstream>
#include <chrono>
#include <cassert>

#include "aes.h"
#include "kalyna.h"
#include "rc4.h"
#include "salsa20.h"

#include "sha256.h"
#include "kupyna.h"

#define RUN_Cipher 1
#define RUN_Hash 1

#define RUN_AES 1
#define RUN_KALYNA 0
#define RUN_RC4 1
#define RUN_SALSA20 1

#define RUN_SHA256 1
#define RUN_KUPYNA 1

size_t constexpr test_runs = 1u << 3u;
size_t const microseconds_in_a_second = 1000 * 1000;

const int kBytesInGigabyte = 1'000'000'000;
const int kBytesIn100Mb = 1'000'000;
const int kBytesInMb = 1'000;

const std::string kTestFileName = "test";
const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(uint8_t);

enum ECryptoClass {
	Cipher,
	Hash
};

inline bool FileExists(const std::string& name) {
	std::ifstream f(name.c_str());
	return f.good();
}

void GenerateData(const int& kDataSize, std::string& fileName) {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> distrib(std::numeric_limits<uint8_t>::min(), std::numeric_limits<uint8_t>::max());

	std::ostringstream os;
	os << kDataSize;
	fileName = kTestFileName + os.str() + ".bin";

	std::cout << "Starting data generation" << std::endl;

	if (!FileExists(fileName)) {
		std::ofstream test_file;
		test_file.open(fileName, std::ios::out | std::ios::binary);

		if (test_file.is_open()) {
			for (int i = 0; i < kDataSize; i++) {
				test_file << (unsigned char)distrib(gen);
			}
			test_file.close();
		}
	}

	std::cout << "Data generation finished" << std::endl;
}

void MeasureCiphers(const int& kDataSize, uint8_t* input_data)
{
#if RUN_AES
	AES aes(256);
	unsigned char iv[] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	unsigned char key_aes[] =
	{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	unsigned int len;

	printf("Start AES_CBC\n");
	auto const& before_aes_cbc = std::chrono::high_resolution_clock::now();

	for (size_t test = 0; test < test_runs; test++) {
		for (int i = 0; i < kDataSize; i += BLOCK_BYTES_LENGTH) {
			unsigned char* out = aes.EncryptCBC(input_data + i, BLOCK_BYTES_LENGTH, key_aes, iv, len);
			unsigned char* innew = aes.DecryptCBC(out, BLOCK_BYTES_LENGTH, key_aes, iv);
			delete[] out;
		}
	}

	auto const& after_aes_cbc = std::chrono::high_resolution_clock::now();

	printf(
		"AES_CBC(%u) on %u bytes took %.6lfs\n",
		256,
		kDataSize,
		static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_aes_cbc - before_aes_cbc).count())
		/ static_cast<double>(test_runs * microseconds_in_a_second));

	printf("Start AES_ECB\n");
	auto const& before_aes_ecb = std::chrono::high_resolution_clock::now();

	for (size_t test = 0; test < test_runs; test++) {
		for (int i = 0; i < kDataSize; i += BLOCK_BYTES_LENGTH) {
			unsigned char* out = aes.EncryptECB(input_data + i, BLOCK_BYTES_LENGTH, key_aes, len);
			unsigned char* innew = aes.DecryptECB(out, BLOCK_BYTES_LENGTH, key_aes);
			delete[] out;
		}
	}

	auto const& after_aes_ecb = std::chrono::high_resolution_clock::now();

	printf(
		"AES_ECB(%u) on %u bytes took %.6lfs\n",
		256,
		kDataSize,
		static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_aes_ecb - before_aes_ecb).count())
		/ static_cast<double>(test_runs * microseconds_in_a_second));

	printf("Start AES_CFB\n");
	auto const& before_aes_cfb = std::chrono::high_resolution_clock::now();

	for (size_t test = 0; test < test_runs; test++) {
		for (int i = 0; i < kDataSize; i += BLOCK_BYTES_LENGTH) {
			unsigned char* out = aes.EncryptCFB(input_data + i, BLOCK_BYTES_LENGTH, key_aes, iv, len);
			unsigned char* innew = aes.DecryptCFB(out, BLOCK_BYTES_LENGTH, key_aes, iv);
			delete[] out;
		}
	}

	auto const& after_aes_cfb = std::chrono::high_resolution_clock::now();

	printf(
		"AES_CFB(%u) on %u bytes took %.6lfs\n",
		256,
		kDataSize,
		static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_aes_cfb - before_aes_cfb).count())
		/ static_cast<double>(test_runs * microseconds_in_a_second));

	printf("Start AES_OFB\n");
	auto const& before_aes_ofb = std::chrono::high_resolution_clock::now();

	for (size_t test = 0; test < test_runs; test++) {
		for (int i = 0; i < kDataSize; i += BLOCK_BYTES_LENGTH) {
			unsigned char* out = aes.EncryptOFB(input_data + i, BLOCK_BYTES_LENGTH, key_aes, iv, len);
			unsigned char* innew = aes.DecryptOFB(out, BLOCK_BYTES_LENGTH, key_aes, iv);
			delete[] out;
		}
	}

	auto const& after_aes_ofb = std::chrono::high_resolution_clock::now();

	printf(
		"AES_OFB(%u) on %u bytes took %.6lfs\n",
		256,
		kDataSize,
		static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_aes_ofb - before_aes_ofb).count())
		/ static_cast<double>(test_runs * microseconds_in_a_second));

	printf("Start AES_CTR\n");
	auto const& before_aes_ctr = std::chrono::high_resolution_clock::now();

	for (size_t test = 0; test < test_runs; test++) {
		for (int i = 0; i < kDataSize; i += BLOCK_BYTES_LENGTH) {
			unsigned char* out = aes.EncryptCTR(input_data + i, BLOCK_BYTES_LENGTH, key_aes, len);
			unsigned char* innew = aes.DecryptCTR(out, BLOCK_BYTES_LENGTH, key_aes);
			delete[] out;
		}
	}

	auto const& after_aes_ctr = std::chrono::high_resolution_clock::now();

	printf(
		"AES_CTR(%u) on %u bytes took %.6lfs\n",
		256,
		kDataSize,
		static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_aes_ctr - before_aes_ctr).count())
		/ static_cast<double>(test_runs * microseconds_in_a_second));
#endif //AES

#if RUN_KALYNA
	Kalyna kalyna(256, 256);
	uint64_t key44_e[4] =
	{ 0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL };
	kalyna.KeyExpand(key44_e);
	uint64_t input[4], ciphered_text[4], output[4];

	printf("Start Kalyna\n");
	auto const& before_kalyna = std::chrono::high_resolution_clock::now();

	for (size_t test = 0; test < test_runs; test++) {
		for (int i = 0; i < kDataSize; i += BLOCK_BYTES_LENGTH) {
			memcpy(input, input_data, BLOCK_BYTES_LENGTH);
			kalyna.Encipher(input, ciphered_text);
			kalyna.Decipher(ciphered_text, output);
		}
	}

	auto const& after_kalyna = std::chrono::high_resolution_clock::now();

	printf(
		"Kalyna(%u, %u) on %u bytes took %.6lfs\n",
		256, 256,
		kDataSize,
		static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_kalyna - before_kalyna).count())
		/ static_cast<double>(test_runs * microseconds_in_a_second));
#endif //KALYNA

#if RUN_RC4
	printf("Start RC4\n");

	RC4 rc4;
	unsigned char key_rc4[] =
	{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

	uint8_t* enc = new uint8_t[kDataSize];
	uint8_t* dec = new uint8_t[kDataSize];

	auto const& before_rc4 = std::chrono::high_resolution_clock::now();

	for (size_t test = 0; test < test_runs; test++) {
		//Encipher
		rc4.SetKey(key_rc4, sizeof key_rc4);
		rc4.Encrypt(input_data, enc, kDataSize);

		//Decipher
		rc4.SetKey(key_rc4, sizeof key_rc4);
		rc4.Decrypt(enc, dec, kDataSize);
	}

	auto const& after_rc4 = std::chrono::high_resolution_clock::now();

	delete[] enc;
	delete[] dec;

	printf(
		"RC4(%u) on %u bytes took %.6lfs\n",
		32,
		kDataSize,
		static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_rc4 - before_rc4).count())
		/ static_cast<double>(test_runs * microseconds_in_a_second));

#endif //RC4

#if RUN_SALSA20
	printf("Start SALSA20\n");
	auto const& before_salsa20 = std::chrono::high_resolution_clock::now();

	Salsa20 salsa20(256);

	uint8_t key_salsa[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	uint8_t n[8] = { 101, 102, 103, 104, 105, 106, 107, 108 };

	for (size_t test = 0; test < test_runs; test++) {
		salsa20.Encrypt(key_salsa, n, 0, input_data, kDataSize);
		salsa20.Decrypt(key_salsa, n, 0, input_data, kDataSize);
	}
	auto const& after_salsa20 = std::chrono::high_resolution_clock::now();

	printf(
		"Salsa20(%u) on %u bytes took %.6lfs\n",
		256,
		kDataSize,
		static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(after_salsa20 - before_salsa20).count())
		/ static_cast<double>(test_runs * microseconds_in_a_second));

#endif //SALSA20
}

void MeasureHashFunctions(const int& kDataSize, uint8_t* input_data)
{
}

void Measurement(const int& kDataSize, const std::string& fileName, ECryptoClass forClass) {
	auto* input_data = new uint8_t[kDataSize];
	if (FileExists(fileName)) {
		std::ifstream input(fileName.c_str(), std::ios::in | std::ios::binary);
		if (input.is_open()) {
			for (int i = 0; i < kDataSize; i++) {
				input >> input_data[i];
			}
		}
	}
	else {
		std::cout << "Couldn't find testing file" << std::endl;
		exit(1);
	}

	switch (forClass)
	{
	case ECryptoClass::Cipher:
		MeasureCiphers(kDataSize, input_data);
		break;
	case ECryptoClass::Hash:
		MeasureHashFunctions(kDataSize, input_data);
		break;
	default:
		break;
	}

	delete[] input_data;
}

int main() {
	std::string TestFile;
	GenerateData(kBytesInMb, TestFile);
#if RUN_Cipher
	Measurement(kBytesInMb, TestFile, ECryptoClass::Cipher);
#endif //RUN_Cipher
#if RUN_Hash
	Measurement(kBytesInMb, TestFile, ECryptoClass::Hash);
#endif //RUN_Hash
	return 0;
}
