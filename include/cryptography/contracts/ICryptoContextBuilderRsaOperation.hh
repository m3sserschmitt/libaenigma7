#ifndef I_CRYPTO_CONTEXT_BUILDER_RSA_OPERATION
#define I_CRYPTO_CONTEXT_BUILDER_RSA_OPERATION

#include "ICryptoContextBuilderKeyData.hh"

class ICryptoContextBuilderRsaOperation
{
public:
    virtual ~ICryptoContextBuilderRsaOperation() {}
    virtual ICryptoContextBuilderKeyData *useSignature() = 0;
    virtual ICryptoContextBuilderKeyData *useSignatureVerification() = 0;
    virtual ICryptoContextBuilderKeyData *useSealing() = 0;
    virtual ICryptoContextBuilderKeyData *useUnsealing() = 0;
};

#endif
