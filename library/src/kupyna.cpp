#include <stdexcept>

#include "kupyna.h"
#include "tables.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"

Kupyna::Kupyna(int size)
{
	switch (size) {
	case 256: {
		Init(64 / byte_size, 512, 512 / byte_size, 512 / dword_size, 256 / byte_size, 10, 8);
		break;
	}
	case 384: {
		Init(64 / byte_size, 1024, 1024 / byte_size, 1024 / dword_size, 384 / byte_size, 14, 16);
		break;
	}
	case 512: {
		Init(64 / byte_size, 1024, 1024 / byte_size, 1024 / dword_size, 512 / byte_size, 14, 16);
		break;
	}
	default: {
		throw std::invalid_argument("Incorrect size");
	}
	}
}

uint64_t* Kupyna::Hash(uint64_t* message, size_t blocks)
{
	uint64_t* state = (uint64_t*)malloc(rows_count * state_rows);
	uint64_t* t1 = (uint64_t*)malloc(rows_count * state_rows);
	uint64_t* t2 = (uint64_t*)malloc(rows_count * state_rows);
	uint64_t* cur_msg;

	memset(state, 0, rows_count * state_rows);

	((uint64_t*)&state[0])[0] = 0x80;

	if (block_size == 512) {

		((uint64_t*)&state[0])[0] >>= 1;
	}

	for (int i = 0; i < blocks; i++) {
		cur_msg = message + i * block_dwsize;
		XORArr(t1, state, cur_msg);
		memcpy(t2, cur_msg, block_bsize);

		TMapXOR(t1);
		TMapAdd(t2);

		XORArr(state, state, t1, t2);
	}

	memcpy(t1, state, block_bsize);
	TMapXOR(t1);
	XORArr(state, state, t1);

	uint64_t* out = new uint64_t[message_diggest_bsize];
	memcpy(out, state, message_diggest_bsize);

	free(state);
	free(t1);
	free(t2);

	return out;
}

void Kupyna::ToEndian(uint64_t* state, size_t size)
{
	uint64_t tmp[8];

	for (size_t i = 0; i < size; i++) {
		uint64_t* state_row = (uint64_t*)&state[i];

		for (size_t j = 0; j < 8; j++) {
			tmp[7 - j] = state_row[j];
		}

		state[i] = ((uint64_t*)tmp)[0];
	}
}

void Kupyna::Init(size_t msg_bsize, const size_t blk_size, const size_t blk_bsize, size_t blk_dwsize, const size_t msg_diggest_bsize, const size_t rnd, const size_t st_rows)
{
	message_bsize = msg_bsize;
	block_size = blk_size;
	block_bsize = block_bsize;
	block_dwsize = blk_dwsize;
	message_diggest_bsize = msg_diggest_bsize;
	rounds = rnd; 
	state_rows = st_rows;
}

void Kupyna::TMapXOR(uint64_t* state)
{
	for (size_t i = 0; i < rounds; i++) {
		XORRoundKey(state, i);
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
	}
}

void Kupyna::TMapAdd(uint64_t* state)
{
	for (size_t i = 0; i < rounds; i++) {
		AddRoundKey(state, i);
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
	}
}

void Kupyna::SubBytes(uint64_t* state)
{
	for (size_t clmn = 0; clmn < state_rows; clmn++) {
		uint64_t* state_clmn = (uint64_t*)&state[clmn];
		for (size_t row = 0; row < rows_count; row++) {
			state_clmn[row] = s_box[row % s_box_dimensions][HighBits(state_clmn[row])]
				[LowBits(state_clmn[row])];
		}
	}
}

void Kupyna::ShiftRows(uint64_t* state)
{
	size_t i;
	for (i = 0; i < rows_count - 1; i++) {
		size_t shift_s = i;

		for (int j = 0; j < shift_s; j++) {
			uint64_t swp = ((uint64_t*)&state[state_rows - 1])[i];

			for (int k =state_rows - 1; k > 0; k--) {
				((uint64_t*)&state[k])[i] = ((uint64_t*)&state[k - 1])[i];
			}

			((uint64_t*)&state[0])[i] = swp;
		}
	}

	size_t shift_s = block_size == 512 ? i : 11;

	for (int j = 0; j < shift_s; j++) {
		uint64_t swp = ((uint64_t*)&state[state_rows - 1])[i];

		for (int k = state_rows - 1; k > 0; k--) {
			((uint64_t*)&state[k])[i] = ((uint64_t*)&state[k - 1])[i];
		}

		((uint64_t*)&state[0])[i] = swp;
	}
}

void Kupyna::MixColumns(uint64_t* state)
{
	MMult(state, mds_matrix);
}

void Kupyna::XORRoundKey(uint64_t* state, size_t round)
{
	for (size_t i = 0; i < state_rows; i++) {
		((uint64_t*)&state[i])[0] ^= (i << 4) ^ round;
	}
}

void Kupyna::AddRoundKey(uint64_t* state, size_t round)
{
	for (size_t i = 0; i < state_rows; i++) {
		state[i] += 0x00F0F0F0F0F0F0F3 ^ ((state_rows - i - 1) << 4);
	}
}

void Kupyna::XORArr(uint64_t* dest, uint64_t* state, uint64_t* msg)
{
	for (size_t i = 0; i < state_rows; i++) {
		dest[i] = state[i] ^ msg[i];
	}
}

void Kupyna::XORArr(uint64_t* dest, uint64_t* state, uint64_t* t1, uint64_t* t2)
{
	for (size_t i = 0; i < state_rows; i++) {
		dest[i] = state[i] ^ t1[i] ^ t2[i];
	}
}

void Kupyna::MMult(uint64_t* state, const uint64_t mat[8][8])
{
	uint64_t product;
	uint64_t result;

	for (int col = 0; col < state_rows; col++) {
		result = 0;

		for (int row = rows_count - 1; row >= 0; row--) {
			product = 0;
			for (int i = rows_count - 1; i >= 0; i--) {
				product ^= GFMult(((uint64_t*)&state[col])[i], mat[row][i]);
			}

			result |= (uint64_t)product << (row * rows_count);
		}

		state[col] = result;
	}
}

std::uint64_t Kupyna::GFMult(uint64_t x, uint64_t y)
{
	uint64_t r = 0;
	uint64_t hbit = 0;

	for (size_t i = 0; i < byte_size; i++) {
		if ((y & 0x1) == 1) {
			r ^= x;
		}

		hbit = x & 0x80;
		x <<= 1;

		if (hbit == 0x80) {
			x ^= 0x011d;
		}

		y >>= 1;
	}

	return r;
}

void Kupyna::PadBlock(uint64_t* msg_block, uint64_t size)
{
	size_t blk_size = size % block_size;
	size_t pad_zeros = block_size - blk_size - 96;
	uint64_t* msg = (uint64_t*)msg_block;

	msg[block_size / byte_size] = 0x80;
	memset(msg + blk_size / byte_size + 1, 0, pad_zeros / byte_size);

	for (size_t i = 0; i < 12; i++) {
		if (i < sizeof(uint64_t)) {
			*(msg + block_bsize - i - 1) = ((uint64_t*)&size)[i];
		}
		else {
			*(msg + block_bsize - i - 1) = 0;
		}
	}
}

int Kupyna::ProofOfWork(uint64_t* in, size_t blocks, size_t zeros_count, uint64_t* out)
{
	if (zeros_count >= 64) {
		return -1;
	}

	uint64_t x = 0;
	size_t i = 0;

	do {
		in[blocks * block_dwsize + i] = x;
		out = Hash(in, blocks + 1);
		x++;

		if (x == 0xFFFFFFFFFFFFFFFF) {
			i++;
		}
	} while (CMPBits(out[message_diggest_bsize / sizeof(uint64_t) - 1], 0, zeros_count) == 0);

	return 0;
}

int Kupyna::CMPBits(uint64_t v1, uint64_t v2, size_t count)
{
	if (((v1 | v2) & (0xFFFFFFFFFFFFFFFF >> (64 - count))) != 0) {
		return 0;
	}
	return 1;
}
