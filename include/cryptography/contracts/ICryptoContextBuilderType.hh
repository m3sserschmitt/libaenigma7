#ifndef I_CRYPTO_CONTEXT_BUILDER_TYPE
#define I_CRYPTO_CONTEXT_BUILDER_TYPE

#include "ICryptoContextBuilderOperation.hh"
#include "ICryptoContextBuilderRsaOperation.hh"

class ICryptoContextBuilderType
{
public:
    virtual ICryptoContextBuilderRsaOperation *useRsa() = 0;
    virtual ICryptoContextBuilderOperation *useAes() = 0;
};

#endif
