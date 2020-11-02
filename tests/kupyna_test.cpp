#include "gtest/gtest.h"
#include "kupyna.h"

TEST(Kupyna, AddRoundKey_Test) {
    uint64_t state[8] = { 0x0001020304050607, 0x08090A0B0C0D0E0F, 0x1011121314151617,
                    0x18191A1B1C1D1E1F, 0x2021222324252627, 0x28292A2B2C2D2E2F,
                    0x3031323334353637, 0x38393A3B3C3D3E3F };

    Kupyna kupyna = Kupyna(256);

    kupyna.ToEndian(state, 8);

    uint64_t expected[8] = { 0xF3F1F2F3F4F5F677, 0xFBF9FAFBFCFDFE6F, 0x0302030405060768,
                       0x0B0A0B0C0D0E0F60, 0x1312131415161758, 0x1B1A1B1C1D1E1F50,
                       0x2322232425262748, 0x2B2A2B2C2D2E2F40 };
    kupyna.ToEndian(expected, 8);

    kupyna.AddRoundKey(state, 0);

    ASSERT_FALSE(memcmp(expected, state, kupyna.state_rows));
}

TEST(Kupyna, SubBytes_Test) {
    uint64_t state[8] = { 0x1101020304050607, 0x08090A0B0C0D0E0F, 0x1011121314151617,
                       0x18191A1B1C1D1E1F, 0x2021222324252627, 0x28292A2B2C2D2E2F,
                       0x3031323334353637, 0x38393A3B3C3D3E3F };
    uint64_t expected[8] = { 0xF3BB9A4D6BCB452A, 0x713ADFB31790511F, 0x6D152B3DC91CBB83,
                       0x795C71D56F5716BD, 0x3EF6C002B4F4AD11, 0x1F0F7A5E496DD166,
                       0x9226C445D15DB794, 0xF4140E1A5810B2DF };

    Kupyna kupyna = Kupyna(256);

    kupyna.ToEndian(state, 8);
    kupyna.ToEndian(expected, 8);

    kupyna.SubBytes(state);
    ASSERT_FALSE(memcmp(expected, state, kupyna.state_rows));
}

TEST(Kupyna, ShiftRows_Test) {
    uint64_t state[8] = { 0xF3BB9A4D6BCB452A, 0x713ADFB31790511F, 0x6D152B3DC91CBB83,
						0x795C71D56F5716BD, 0x3EF6C002B4F4AD11, 0x1F0F7A5E496DD166,
						0x9226C445D15DB794, 0xF4140E1A5810B2DF };

    Kupyna kupyna = Kupyna(256);
    kupyna.ToEndian(state, 8);

    kupyna.ShiftRows(state);


    uint64_t expected[8] = { 0xF314C45EB457BB1F, 0x71BB0E4549F41683, 0x6D3A9A1AD16DADBD,
					   0x7915DF4D585DD111, 0x3E5C2BB36B10B766, 0x1FF6713D17CBB294,
					   0x920FC0D5C99045DF, 0xF4267A026F1C512A };
    kupyna.ToEndian(expected, 8);

	kupyna.ToEndian(state, 8);
	ASSERT_FALSE(memcmp(expected, state, kupyna.state_rows));
}
