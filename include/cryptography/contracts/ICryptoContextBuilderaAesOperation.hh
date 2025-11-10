#ifndef I_CRYPTO_CONTEXT_BUILDER_AES_OPERATION
#define I_CRYPTO_CONTEXT_BUILDER_AES_OPERATION

#include "ICryptoContextBuilderKeyData.hh"

class ICryptoContextBuilderAesOperation
{
public:
    virtual ~ICryptoContextBuilderAesOperation() {}
    virtual ICryptoContextBuilderKeyData *useEncryption() = 0;
    virtual ICryptoContextBuilderKeyData *useDecryption() = 0;
};

#endif
