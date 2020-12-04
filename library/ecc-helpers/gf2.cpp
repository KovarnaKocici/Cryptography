#include "gf2.h"
#include <cassert>
#include <iostream>
#include "transforms.h"
#include "gmpxx.h"

mpz_class GF::ConvertToFx(std::vector<mpz_class> powers){
    mpz_class result(0);
    mpz_class temp(0);
    mpz_class one(1);

    for(auto power : powers) {
        mpz_set(temp.get_mpz_t() , mpz_class(one<< power.get_ui()).get_mpz_t());
        mpz_add(result.get_mpz_t(), result.get_mpz_t(), temp.get_mpz_t());
#if DEBUG
        printf(("power = %i, temp %i, result %i"),power.get_ui(), mpz_out_str(stdout, 10, temp.get_mpz_t()), mpz_out_str(stdout, 10, result.get_mpz_t())) ;
        printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
    }
    return result;
}

unsigned int GF::M(mpz_class f) {
 return BitLength(f) - 1;
}

mpz_class GF::Add(mpz_class a, mpz_class b){
    return a^b;
}

mpz_class GF::Mult(mpz_class a, mpz_class b, mpz_class f){
    unsigned int m(M(f));
#if DEBUG
    printf("\nMULT");
    printf("\nm = ");
    mpz_out_str(stdout, 10,m.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
    printf("\nf = ");
    mpz_out_str(stdout, 10, f.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
    printf("m = ");
    mpz_out_str(stdout, 10, m.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
    printf("a = ");
    mpz_out_str(stdout, 10, a.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
    printf("b = ");
    mpz_out_str(stdout, 10, b.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
    assert(BitLength(a) <= m);
    assert(BitLength(b) <= m);

    mpz_class one(1);
    mpz_class mask((one << m) - 1);
    mpz_class p(0);
    while(a > 0 && b > 0)
    {
        mpz_class cond1(b & one);// b&1
        if (cond1) {
            p ^= a;
#if DEBUG
            printf("cond1 \np = ");
            mpz_out_str(stdout, 10, p.get_mpz_t());
            printf("\n------------------------------------------------------------------------------------------\n");
#endif// DEBUG
        }
        mpz_class cond2(a & (one << mpz_class(m - one).get_ui())); // a & (1<< (m-1))
        if (cond2)
            mpz_set(a.get_mpz_t() , mpz_class(((a << one.get_ui()) ^ f) & mask).get_mpz_t());
        else {
            a =  a << one.get_ui();
            a = a & mask;
#if DEBUG
            printf("else \na = ");
            mpz_out_str(stdout, 10, a.get_mpz_t());
            printf("\n------------------------------------------------------------------------------------------\n");
#endif// DEBUG
        }
        b >>= one.get_ui();
#if DEBUG
        printf("\nb = ");
        mpz_out_str(stdout, 10, b.get_mpz_t());
        printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
    }
    return p;
}

mpz_class GF::Div(mpz_class a, mpz_class b, mpz_class f){
    return Mult(a, Inv(b, f), f);
}

mpz_class GF::ModPow(mpz_class a, mpz_class pow, mpz_class f){
#if DEBUG
    printf("\nModPow");
    printf("\na = ");
    mpz_out_str(stdout, 10, a.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
    printf("\npow = ");
    mpz_out_str(stdout, 10, pow.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
    std::string str_pow = IntToStr(pow);//pow.get_str(); // IntToStr(pow);
    mpz_class multiplier(a);
    mpz_class result(1);
    for (int i = str_pow.length() - 1;  i > -1; --i) {
        if (str_pow[i] == '1') {
            mpz_set(result.get_mpz_t(), Mult(result, multiplier, f).get_mpz_t());
#if DEBUG
            std::cout << i << std::endl;
            printf("\nresult = ");
            mpz_out_str(stdout, 10, result.get_mpz_t());
            printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
        }
        mpz_set(multiplier.get_mpz_t(), Square(multiplier, f).get_mpz_t());
#if DEBUG
        printf("\nmultiplier = ");
        mpz_out_str(stdout, 10, multiplier.get_mpz_t());
        printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
    }
#if DEBUG
    printf("\nModPow result = ");
    mpz_out_str(stdout, 10, result.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
    return result;
}

mpz_class GF::Square(mpz_class a, mpz_class f){
    return Mult(a,a,f);
}

mpz_class GF::Sqrt(mpz_class a, mpz_class f){
    unsigned int m(M(f));
    mpz_class pow(0);
    mpz_ui_pow_ui(pow.get_mpz_t(), 2, m - 1);
    return ModPow(a, pow, f);
}

mpz_class GF::Inv(mpz_class a, mpz_class f){
    unsigned int m(M(f));
#if DEBUG
    printf("\nINV ");
    printf("\nm = ");
    mpz_out_str(stdout, 10, m.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
    mpz_class pow(0);
    mpz_ui_pow_ui(pow.get_mpz_t(), 2, m);
#if DEBUG
    printf("\nres = ");
    mpz_out_str(stdout, 10, res.get_mpz_t());
    printf("\n------------------------------------------------------------------------------------------\n");
#endif //DEBUG
    return ModPow(a, pow - 2, f);
}

mpz_class GF::Trace(mpz_class x, mpz_class m, mpz_class f){
    mpz_class t(x);
    for (mpz_class i = 1; i <m; ++i)
        mpz_set(t.get_mpz_t(), Add(ModPow(t, 2, f), x).get_mpz_t());
    assert (t == 0 || t == 1);
    return t;
}

mpz_class GF::HalfTrace(mpz_class x, mpz_class m, mpz_class f){
    assert((m & 1) > 0);
    mpz_class t (x);
    mpz_class max(((m - 1) / 2) + 1);
    for( mpz_class i = 1; i < max; ++i) {
        mpz_set(t.get_mpz_t(), Add(ModPow(t, 4, f), x).get_mpz_t());
    }
    return t;
}