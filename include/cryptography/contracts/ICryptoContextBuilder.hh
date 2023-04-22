#ifndef I_CRYPTO_CONTEXT_BUILDER
#define I_CRYPTO_CONTEXT_BUILDER

#include "ICryptoContext.hh"

class ICryptoContextBuilder
{
public:
    virtual ICryptoContext *build() = 0;
};

#endif
