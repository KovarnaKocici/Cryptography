#ifndef AES_KALYNA_INCLUDE_ECC_TRANSFORMS_H_
#define AES_KALYNA_INCLUDE_ECC_TRANSFORMS_H_

#include <string>
#include <gmpxx.h>

#define DEBUG 0

std::string IntToStr(mpz_class num);
mpz_class StrToInt(std::string num);
unsigned int BitLength(const mpz_class& number);
#endif //AES_KALYNA_INCLUDE_ECC_TRANSFORMS_H_