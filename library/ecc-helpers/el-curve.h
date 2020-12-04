#ifndef AES_KALYNA_INCLUDE_ElCRUVE_H_
#define AES_KALYNA_INCLUDE_ElCRUVE_H_

#include <cstdint>
#include <gmpxx.h>

class Point
{
private:

    mpz_class _x, _y;

public:
    Point();
    Point(mpz_class x, mpz_class y);

    mpz_class getX();
    mpz_class getY();

    void setX(mpz_class x);
    void setY(mpz_class y);

    const Point& operator = (const Point& other);
    const bool operator==(const Point& rhs) const;

    friend std::ostream& operator << (std::ostream& os, const Point& number);

    ~Point();
};

class ElipticCurve {
private:
    mpz_class _A, _B, _f, _mask;
    unsigned int _m;
    Point _zero;

public:
    Point getZero(){return _zero;}
    mpz_class getF() const {return _f;}
    unsigned int getM() const {return _m;}
    mpz_class getMask() const {return _mask;}

    ElipticCurve(mpz_class A, mpz_class B, unsigned int m, std::vector<mpz_class> powers);

    Point AddPoints(Point p1, Point q1);

    Point DoublePoint(Point p);

    static Point NegPoint(Point point);

    Point MultPoint(Point point, mpz_class d);

    bool PointOnCurve(Point point);

    Point GenPoint();

    mpz_class RandFieldElement();

    std::pair<mpz_class, mpz_class> SolveQuadEq(mpz_class u, mpz_class w);
};
#endif// AES_KALYNA_INCLUDE_ElCRUVE_H_