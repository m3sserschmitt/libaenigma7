#ifndef I_CRYPTO_CONTEXT_BUILDER_KEY_DATA
#define I_CRYPTO_CONTEXT_BUILDER_KEY_DATA

#include "ICryptoContextBuilder.hh"
#include "../Types.hh"

class ICryptoContextBuilderKeyData
{
public:
    virtual ICryptoContextBuilder *setKey256(ConstBytes key) = 0;
    virtual ICryptoContextBuilder *setKey(ConstPlaintext key) = 0;
    virtual ICryptoContextBuilder *setKey(ConstPlaintext Key, Plaintext passphrase) = 0;
    virtual ICryptoContextBuilder *readKeyData(ConstPlaintext path, Plaintext passphrase) = 0;
    virtual ICryptoContextBuilder *readKeyData(ConstPlaintext path) = 0;
};

#endif