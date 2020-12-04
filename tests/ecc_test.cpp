#include "ecc.h"
#include "../ecc-helpers/el-curve.h"
#include "gtest/gtest.h"
#include "gmpxx.h"

TEST(ECC, ECC_163) {
    unsigned char input_data[13] = "Hello World!";
    mpz_class A_163(1);
    mpz_class B_163;
    B_163.set_str("5FF6108462A2DC8210AB403925E638A19C1455D21", 16);
    unsigned int m_163 = 163;
    mpz_class n_163;
    n_163.set_str("400000000000000000002BEC12BE2262D39BCF14D", 16);
    std::vector<mpz_class> powers_163 = {163, 7, 6, 3, 0};
    std::cout << "\nInitializing ECC 163";
    ECC ecc163 = ECC(A_163, B_163, m_163, n_163, powers_163);
    std::cout << "\nRunning ECC 163";
    std::tuple<unsigned char *, size_t, std::string> signature_163 = ecc163.Sign(input_data, sizeof(input_data) / sizeof(char));
    bool verified_163 = ecc163.ValidateSignature(signature_163);
    std::cout << "\nVerified:" << verified_163;
    ASSERT_FALSE(!verified_163);

}