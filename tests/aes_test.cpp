#include "aes.h"
#include "gtest/gtest.h"

const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);

TEST(KeyLengths, KeyLength128) {
  AES aes(128);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
       0x5a};
  unsigned int len = 0;
  unsigned char *out = aes.EncryptECB(plain, 16, key, len);

  ASSERT_FALSE(memcmp(right, out, BLOCK_BYTES_LENGTH));
  ASSERT_EQ(BLOCK_BYTES_LENGTH, len);
  delete[] out;
}

TEST(KeyLengths, KeyLength192) {
  AES aes(192);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f, 0x10, 0x11,
       0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
  unsigned char right[] =
      {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71,
       0x91};
  unsigned int len;

  unsigned char *out = aes.EncryptECB(plain, 16, key, len);
  ASSERT_FALSE(memcmp(right, out, BLOCK_BYTES_LENGTH));
  ASSERT_EQ(16, len);
  delete[] out;
}

TEST(KeyLengths, KeyLength256) {
  AES aes(256);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f, 0x10, 0x11,
       0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned char right[] =
      {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
       0x89};
  unsigned int len = 0;

  unsigned char *out = aes.EncryptECB(plain, 16, key, len);
  ASSERT_FALSE(memcmp(right, out, BLOCK_BYTES_LENGTH));
  ASSERT_EQ(16, len);
  delete[] out;
}

TEST(ECB, EncryptDecrypt) {
  AES aes(256);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};

  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f, 0x10, 0x11,
       0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned int len = 0;

  unsigned char *out = aes.EncryptECB(plain, BLOCK_BYTES_LENGTH, key, len);
  unsigned char *innew = aes.DecryptECB(out, BLOCK_BYTES_LENGTH, key);
  ASSERT_FALSE(memcmp(innew, plain, BLOCK_BYTES_LENGTH));
  delete[] out;
  delete[] innew;
}

TEST(ECB, OneBlockWithoutByteEncrypt) {
  AES aes(128);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x7c, 0x99, 0xf4, 0x2b, 0x6e, 0xe5, 0x03, 0x30, 0x9c, 0x6c, 0x1a, 0x67, 0xe9, 0x7a, 0xc2,
       0x42};
  unsigned int len = 0;
  unsigned char
      *out = aes.EncryptECB(plain, (BLOCK_BYTES_LENGTH - 1 * sizeof(unsigned char)), key, len);

  ASSERT_EQ(BLOCK_BYTES_LENGTH, len);
  ASSERT_FALSE(memcmp(right, out, len));

  delete[] out;
}

TEST(ECB, OneBlockPlusOneByteEncrypt) {
  AES aes(128);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff, 0xaa};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
       0x5a,
       0x08, 0x69, 0xe8, 0x81, 0x8a, 0x81, 0x78, 0x9a, 0x72, 0x3d, 0x26, 0x16, 0x40, 0x0d, 0x31,
       0xa9
      };
  unsigned int len = 0;
  unsigned char
      *out = aes.EncryptECB(plain, (BLOCK_BYTES_LENGTH + 1) * sizeof(unsigned char), key, len);

  ASSERT_EQ(2 * BLOCK_BYTES_LENGTH, len);
  ASSERT_FALSE(memcmp(right, out, len));

  delete[] out;
}

TEST(ECB, TwoBlocksEncrypt) {
  AES aes(128);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff,
       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
       0x1f};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
       0x5a,
       0x07, 0xfe, 0xef, 0x74, 0xe1, 0xd5, 0x03, 0x6e, 0x90, 0x0e, 0xee, 0x11, 0x8e, 0x94, 0x92,
       0x93,
      };
  unsigned int len = 0;
  unsigned char
      *out = aes.EncryptECB(plain, (BLOCK_BYTES_LENGTH * 2) * sizeof(unsigned char), key, len);

  ASSERT_EQ(2 * BLOCK_BYTES_LENGTH, len);
  ASSERT_FALSE(memcmp(right, out, len));

  delete[] out;
}

TEST(ECB, OneBlockDecrypt) {
  AES aes(128);
  unsigned char encrypted[] =
      {0x7c, 0x99, 0xf4, 0x2b, 0x6e, 0xe5, 0x03, 0x30, 0x9c, 0x6c, 0x1a, 0x67, 0xe9, 0x7a, 0xc2,
       0x42};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};
  unsigned int len = 0;
  unsigned char *out = aes.DecryptECB(encrypted, BLOCK_BYTES_LENGTH, key);

  ASSERT_FALSE(memcmp(right, out, len));

  delete[] out;
}

TEST(ECB, TwoBlocksDecrypt) {
  AES aes(128);
  unsigned char encrypted[] =
      {0x7c, 0x99, 0xf4, 0x2b, 0x6e, 0xe5, 0x03, 0x30, 0x9c, 0x6c, 0x1a, 0x67, 0xe9, 0x7a, 0xc2,
       0x42,
       0x7c, 0x99, 0xf4, 0x2b, 0x6e, 0xe5, 0x03, 0x30, 0x9c, 0x6c, 0x1a, 0x67, 0xe9, 0x7a, 0xc2,
       0x42};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff,
       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0x00};
  unsigned int len = 0;
  unsigned char *out = aes.DecryptECB(encrypted, BLOCK_BYTES_LENGTH, key);

  ASSERT_FALSE(memcmp(right, out, len));

  delete[] out;
}

TEST(CBC, EncryptDecrypt) {
  AES aes(256);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};
  unsigned char iv[] =
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f, 0x10, 0x11,
       0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned int len;

  unsigned char *out = aes.EncryptCBC(plain, BLOCK_BYTES_LENGTH, key, iv, len);
  unsigned char *innew = aes.DecryptCBC(out, BLOCK_BYTES_LENGTH, key, iv);
  ASSERT_FALSE(memcmp(innew, plain, BLOCK_BYTES_LENGTH));
  delete[] out;
  delete[] innew;
}

TEST(CBC, TwoBlocksEncrypt) {
  AES aes(128);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff,
       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};
  unsigned char iv[] =
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x1b, 0x87, 0x23, 0x78, 0x79, 0x5f, 0x4f, 0xfd, 0x77, 0x28, 0x55, 0xfc, 0x87, 0xca, 0x96,
       0x4d,
       0x4c, 0x5b, 0xca, 0x1c, 0x48, 0xcd, 0x88, 0x00, 0x3a, 0x10, 0x52, 0x11, 0x88, 0x12, 0x5e,
       0x00};
  unsigned int len;

  unsigned char *out = aes.EncryptCBC(plain, BLOCK_BYTES_LENGTH * 2, key, iv, len);
  ASSERT_EQ(BLOCK_BYTES_LENGTH * 2, len);
  ASSERT_FALSE(memcmp(out, right, BLOCK_BYTES_LENGTH * 2));
  delete[] out;
}

TEST(CBC, TwoBlocksDecrypt) {
  AES aes(128);
  unsigned char encrypted[] =
      {0x1b, 0x87, 0x23, 0x78, 0x79, 0x5f, 0x4f, 0xfd, 0x77, 0x28, 0x55, 0xfc, 0x87, 0xca, 0x96,
       0x4d,
       0x4c, 0x5b, 0xca, 0x1c, 0x48, 0xcd, 0x88, 0x00, 0x3a, 0x10, 0x52, 0x11, 0x88, 0x12, 0x5e,
       0x00};

  unsigned char iv[] =
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff,
       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};

  unsigned char *out = aes.DecryptCBC(encrypted, BLOCK_BYTES_LENGTH * 2, key, iv);

  ASSERT_FALSE(memcmp(out, right, BLOCK_BYTES_LENGTH * 2));
  delete[] out;
}

TEST(CFB, EncryptDecrypt) {
  AES aes(256);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};
  unsigned char iv[] =
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f, 0x10, 0x11,
       0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned int len;

  unsigned char *out = aes.EncryptCFB(plain, BLOCK_BYTES_LENGTH, key, iv, len);
  unsigned char *innew = aes.DecryptCFB(out, BLOCK_BYTES_LENGTH, key, iv);
  ASSERT_FALSE(memcmp(innew, plain, BLOCK_BYTES_LENGTH));
  delete[] out;
  delete[] innew;
}

TEST(CFB, EncryptTwoBlocks) {
  AES aes(128);
  unsigned char plain[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff,
       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};
  unsigned char iv[] =
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x3c, 0x55, 0x3d, 0x01, 0x8a, 0x52, 0xe4, 0x54, 0xec, 0x4e, 0x08, 0x22, 0xc2, 0x8d, 0x55,
       0xec,
       0xe3, 0x5a, 0x40, 0xab, 0x30, 0x29, 0xf3, 0x0c, 0xe1, 0xdb, 0x30, 0x6c, 0xa1, 0x05, 0xcb,
       0xa9};
  unsigned int len;

  unsigned char *out = aes.EncryptCFB(plain, BLOCK_BYTES_LENGTH * 2, key, iv, len);
  ASSERT_EQ(2 * BLOCK_BYTES_LENGTH, len);
  ASSERT_FALSE(memcmp(right, out, BLOCK_BYTES_LENGTH * 2));
  delete[] out;
}

TEST(CFB, DecryptTwoBlocks) {
  AES aes(128);
  unsigned char encrypted[] =
      {0x3c, 0x55, 0x3d, 0x01, 0x8a, 0x52, 0xe4, 0x54, 0xec, 0x4e, 0x08, 0x22, 0xc2, 0x8d, 0x55,
       0xec,
       0xe3, 0x5a, 0x40, 0xab, 0x30, 0x29, 0xf3, 0x0c, 0xe1, 0xdb, 0x30, 0x6c, 0xa1, 0x05, 0xcb,
       0xa9};
  unsigned char iv[] =
      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
       0xff};
  unsigned char key[] =
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
       0x0f};
  unsigned char right[] =
      {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff,
       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
       0xff};

  unsigned char *out = aes.DecryptCFB(encrypted, BLOCK_BYTES_LENGTH * 2, key, iv);
  ASSERT_FALSE(memcmp(right, out, BLOCK_BYTES_LENGTH * 2));
  delete[] out;
}

TEST(OFB, EncryptDecrypt) {
	AES aes(256);
	unsigned char plain[] =
	{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
	 0xff };
	unsigned char iv[] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	 0xff };
	unsigned char key[] =
	{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	 0x0f, 0x10, 0x11,
	 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	unsigned int len;

	unsigned char* out = aes.EncryptOFB(plain, BLOCK_BYTES_LENGTH, key, iv, len);
	unsigned char* innew = aes.DecryptOFB(out, BLOCK_BYTES_LENGTH, key, iv);
	EXPECT_FALSE(memcmp(innew, plain, BLOCK_BYTES_LENGTH));
	delete[] out;
	delete[] innew;
}

TEST(OFB, TwoBlocksEncrypt) {
	AES aes(128);
	unsigned char plain[] =
	{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	unsigned char iv[] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	unsigned char key[] =
	{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	unsigned char expected[] =
	{ 0x3c, 0x55, 0x3d, 0x01, 0x8a, 0x52, 0xe4, 0x54, 0xec, 0x4e, 0x08, 0x22, 0xc2, 0x8d, 0x55, 0xec,
	 0xa3, 0x01, 0xde, 0xc0, 0x19, 0xae, 0xa5, 0xaa, 0x23, 0x3f, 0x27, 0x7e, 0x01, 0x50, 0x85, 0x29 };
	unsigned int len;

	unsigned char* out = aes.EncryptOFB(plain, BLOCK_BYTES_LENGTH * 2, key, iv, len);
	EXPECT_EQ(BLOCK_BYTES_LENGTH * 2, len);
	EXPECT_FALSE(memcmp(out, expected, BLOCK_BYTES_LENGTH * 2));
	delete[] out;
}

TEST(OFB, DecryptTwoBlocks) {
	AES aes(128);
	unsigned char encrypted[] =
	{ 0x3c, 0x55, 0x3d, 0x01, 0x8a, 0x52, 0xe4, 0x54, 0xec, 0x4e, 0x08, 0x22, 0xc2, 0x8d, 0x55, 0xec,
	 0xe3, 0x5a, 0x40, 0xab, 0x30, 0x29, 0xf3, 0x0c, 0xe1, 0xdb, 0x30, 0x6c, 0xa1, 0x05, 0xcb, 0xa9 };
	unsigned char iv[] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	unsigned char key[] =
	{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	unsigned char expected[] =
	{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	 0x40, 0x4a, 0xbc, 0x58, 0x6d, 0xd2, 0x30, 0xd1, 0x4a, 0x7d, 0xbd, 0xa9, 0x6c, 0x88, 0xa0, 0x7f };

	unsigned char* out = aes.DecryptOFB(encrypted, BLOCK_BYTES_LENGTH * 2, key, iv);
	EXPECT_FALSE(memcmp(expected, out, BLOCK_BYTES_LENGTH * 2));
	delete[] out;
}
TEST(CTR, EncryptDecrypt) {
	AES aes(256);
	unsigned char plain[] =
	{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
	 0xff };
	unsigned char iv[] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	 0xff };
	unsigned char key[] =
	{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	 0x0f, 0x10, 0x11,
	 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	unsigned int len;

	unsigned char* out = aes.EncryptCTR(plain, BLOCK_BYTES_LENGTH, key, len);
	unsigned char* innew = aes.DecryptCTR(out, BLOCK_BYTES_LENGTH, key);
	EXPECT_FALSE(memcmp(innew, plain, BLOCK_BYTES_LENGTH));
	delete[] out;
	delete[] innew;
}