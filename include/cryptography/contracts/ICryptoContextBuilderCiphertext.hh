#ifndef I_CRYPTO_CONTEXT_BUILDER_CIPHERTEXT
#define I_CRYPTO_CONTEXT_BUILDER_CIPHERTEXT

#include "ICryptoContextBuilderKeyData.hh"

class ICryptoContextBuilderCiphertext
{
public:
    virtual ICryptoContextBuilderKeyData *setCiphertext(ConstBytes data, Size datalen) = 0;

    virtual ICryptoContextBuilderKeyData *noCiphertext() = 0;
};

#endif
