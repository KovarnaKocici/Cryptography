#include "transforms.h"

std::string IntToStr(mpz_class num) {
    char* temp = mpz_get_str(NULL ,2, num.get_mpz_t());
    return std::string(temp);
    //return tempStr.substr(0, tempStr.length());
}

mpz_class StrToInt(std::string num) {
    return mpz_class(num, 2);
}

unsigned int BitLength(const mpz_class& number)
{
    std::string numSTR = number.get_str(2);
    unsigned int bits = numSTR.length();
#if DEBUG
    printf("BitLength \nbits = ");
    mpz_out_str(stdout, 10, bits.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
#endif // DEBUG
    return bits;
}