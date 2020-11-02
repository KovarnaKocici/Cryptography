#ifndef IS_LIBRARY_INCLUDE_KUPYNA_H_
#define IS_LIBRARY_INCLUDE_KUPYNA_H_

class Kupyna
{
public:
	Kupyna(int size);
	uint64_t* Hash(uint64_t* message, size_t blocks);

	uint64_t HighBits(uint64_t val) { return (val & 0xF0) >> 4; };
	uint64_t LowBits(uint64_t val) { return val & 0x0F; };
	void ToEndian(uint64_t* state, size_t size);

private:
	const size_t rows_count = 8;
	const size_t byte_size = 8;
	const size_t dword_size = 64;
	const size_t dword_bsize = sizeof(uint64_t);
	const size_t s_box_dimensions = 4;

	size_t message_bsize;
	size_t block_size;
	size_t block_bsize;
	size_t block_dwsize;
	size_t message_diggest_bsize;
	size_t rounds;

	void Init(size_t msg_bsize, const size_t blk_size, const size_t blk_bsize, size_t blk_dwsize,
		const size_t msg_diggest_bsize, const size_t rnd, const size_t st_rows);

public:
	size_t state_rows;

	void TMapXOR(uint64_t* state);
	void TMapAdd(uint64_t* state);
	void SubBytes(uint64_t* state);
	void ShiftRows(uint64_t* state);
	void MixColumns(uint64_t* state);
	void XORRoundKey(uint64_t* state, size_t round);
	void AddRoundKey(uint64_t* state, size_t round);
	void XORArr(uint64_t* dest, uint64_t* state, uint64_t* msg);
	void XORArr(uint64_t* dest, uint64_t* state, uint64_t* t1, uint64_t* t2);
	void MMult(uint64_t* state, const uint64_t mat[8][8]);
	uint64_t GFMult(uint64_t x, uint64_t y);
	void PadBlock(uint64_t* msg_block, uint64_t size);

	int ProofOfWork(uint64_t* in, size_t blocks, size_t zeros_count, uint64_t* out);
	int CMPBits(uint64_t v1, uint64_t v2, size_t count);

};
#endif //IS_LIBRARY_INCLUDE_KUPYNA_H_

