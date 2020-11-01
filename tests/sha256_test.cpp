#include <iostream>

#include "sha256.h"
#include "gtest/gtest.h"

TEST(SHA256, Basic_hash_Test) {
	std::string message = "The quick brown fox jumps over the lazy dog";
	std::string correct_hash ="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

	SHA256* sha256 = new SHA256;
	std::string hash = sha256->Hash(message);
	
	EXPECT_TRUE(hash.compare(correct_hash) == 0);

	delete sha256;
}

//TEST(SHA256, Blocksize_hash_Test) {
//	//Test if hash is correct when input is already the correct blocksize
//	SHA256* sha256 = new SHA256;
//	std::vector<unsigned char> message = { '0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6','7','8','9','0','1','2','3' };
//	std::vector<unsigned char> hash = sha256->hash(message);
//	std::vector<unsigned char> correct_hash = { 0x96, 0x74, 0xd9, 0xe0, 0x78, 0x53, 0x5b, 0x7c, 0xec, 0x43, 0x28, 0x43, 0x87, 0xa6, 0xee, 0x39, 0x95, 0x61, 0x88, 0xe7, 0x35, 0xa8, 0x54, 0x52, 0xb0, 0x05, 0x0b, 0x55, 0x34, 0x1c, 0xda, 0x56 };
//	delete sha256;
//
//	if (hash != correct_hash) return TEST_RESULT::TEST_FAILED;
//	return TEST_RESULT::TEST_PASSED;
//}
//
//TEST(SHA256, Reset_Test) {
//	//Checks if internal hash state is properly reset after hashing one message
//	if (sha256_basic_hash() == TEST_RESULT::TEST_FAILED) return TEST_RESULT::TEST_PASSED; //If this occurs the hashing is broken, but we return pass because we are only testing if it fails after succeeding once
//	if (sha256_basic_hash() == TEST_RESULT::TEST_FAILED) return TEST_RESULT::TEST_FAILED;
//	return TEST_RESULT::TEST_PASSED;
//}