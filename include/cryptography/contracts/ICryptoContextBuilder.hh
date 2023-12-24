#ifndef I_CRYPTO_CONTEXT_BUILDER
#define I_CRYPTO_CONTEXT_BUILDER

class ICryptoContextBuilder
{
public:
    virtual ~ICryptoContextBuilder() {}
    virtual CryptoContext *build() = 0;
};

#endif
