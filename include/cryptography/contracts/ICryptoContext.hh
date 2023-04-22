#ifndef I_CRYPTO_CONTEXT_HH
#define I_CRYPTO_CONTEXT_HH

#include "../Types.hh"
#include "../EncrypterData.hh"

class ICryptoContext
{
public:
    virtual bool run() = 0;

    virtual bool setKey256(ConstBytes key) = 0;

    virtual bool setKeyData(ConstPlaintext key, char *plaintext = nullptr) = 0;

    virtual bool readKeyFile(ConstPlaintext path, Plaintext passphrase = nullptr) = 0;

    virtual bool setPlaintext(ConstBytes data, Size datalen) = 0;

    virtual const EncrypterData *getPlaintext() const = 0;

    virtual bool setCiphertext(ConstBytes data, Size datalen) = 0;

    virtual const EncrypterData *getCiphertext() const = 0;
};

#endif
