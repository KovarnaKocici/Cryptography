#include <iostream>

#include "sha256.h"
#include "gtest/gtest.h"

TEST(SHA256, Basic_hash_Test) {
	std::string message = "The quick brown fox jumps over the lazy dog";
	std::string correct_hash ="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

	SHA256 sha256 = SHA256();
	std::string hash = sha256.Hash(message);
	
	EXPECT_TRUE(hash.compare(correct_hash) == 0);
}