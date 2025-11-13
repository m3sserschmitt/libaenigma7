#ifndef CRYPTO_CONTEXT_HH
#define CRYPTO_CONTEXT_HH

#include "CryptoMachine.hh"
#include "Key.hh"

class CryptoContext
{
private:
    Key *key;
    EvpContext *cipher;
    CryptoMachine *cryptoMachine;

    [[nodiscard]] bool notNullCryptoMachine() const { return this->cryptoMachine != nullptr; }

    void freeKey()
    {
        delete this->key;
        this->key = nullptr;
    }

    void freeCipher()
    {
        delete this->cipher;
        this->cipher = nullptr;
    }

    void freeCryptoMachine()
    {
        delete this->cryptoMachine;
        this->cryptoMachine = nullptr;
    }

public:
    ~CryptoContext() { this->cleanup(); }

    CryptoContext(Key *key, EvpContext *cipher, CryptoMachine *cryptoMachine)
    {
        this->cryptoMachine = cryptoMachine;
        this->key = key;
        this->cipher = cipher;
    }

    CryptoContext(const CryptoContext &) = delete;
    const CryptoContext &operator=(const CryptoContext &) = delete;

    CryptoContext()
    {
        this->cryptoMachine = nullptr;
        this->key = nullptr;
        this->cipher = nullptr;
    }

    bool setInput(const unsigned char *data, unsigned int dataLen)
    {
        if (notNullCryptoMachine())
        {
            this->cryptoMachine->setInput(data, dataLen);
            return true;
        }
        return false;
    }

    [[nodiscard]] const EncrypterResult *getOutput() const
    {
        return this->notNullCryptoMachine() ? this->cryptoMachine->getOutput() : nullptr;
    }

    bool run() { return this->notNullCryptoMachine() and this->cryptoMachine->run(); }

    void cleanup()
    {
        this->freeCryptoMachine();
        this->freeKey();
        this->freeCipher();
    }
};

#endif
