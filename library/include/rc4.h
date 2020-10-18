#ifndef RC4_LIBRARY_INCLUDE_RC4_H_
#define RC4_LIBRARY_INCLUDE_RC4_H_
class RC4 {
public:
    explicit RC4();

    void SetKey(uint8_t k[], uint32_t size);

    void Encrypt(uint8_t plaintext[], uint8_t ciphertext[], uint32_t Len);

private:
    void Swap(uint8_t data[], uint32_t i, uint32_t j);
    //key - scheduling algorithm
    void KSA(uint8_t* key);
    //pseudo - random generation algorithm
    void PRGA(uint8_t plaintext[], uint8_t cipher[], uint32_t Len);

    uint8_t sbox[256];
    size_t sizeKey, prgaIndexA, prgaIndexB;
};

#endif //RC4_LIBRARY_INCLUDE_RC4_H_