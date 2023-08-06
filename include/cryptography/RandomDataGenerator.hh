#ifndef RANDOM_DATA_GENERATOR_HH
#define RANDOM_DATA_GENERATOR_HH

#include "Constants.hh"
#include <random>

class RandomDataGenerator
{
public:
    static Bytes generate(Size len)
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        std::uniform_int_distribution<int> dist(0, 0xff);

        Bytes data = new Byte[len + 1];

        for (Size i = 0; i < len; i++)
        {
            data[i] = dist(rng);
        }

        return data;
    }

    static Bytes generateKey()
    {
        return generate(SYMMETRIC_KEY_SIZE);
    }
};

#endif
