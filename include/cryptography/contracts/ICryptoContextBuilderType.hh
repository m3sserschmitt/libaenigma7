#ifndef I_CRYPTO_CONTEXT_BUILDER_TYPE
#define I_CRYPTO_CONTEXT_BUILDER_TYPE

#include "ICryptoContextBuilderRsaOperation.hh"
#include "ICryptoContextBuilderaAesOperation.hh"

class ICryptoContextBuilderType
{
public:
    virtual ~ICryptoContextBuilderType() {}
    virtual ICryptoContextBuilderRsaOperation *useRsa() = 0;
    virtual ICryptoContextBuilderAesOperation *useAes() = 0;
};

#endif
