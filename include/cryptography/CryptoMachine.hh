#ifndef CRYPTO_MACHINE_HH
#define CRYPTO_MACHINE_HH

#include "Key.hh"
#include "EncrypterResult.hh"

class CryptoMachine
{
    Key *key;
    const EncrypterData *inData;
    const EncrypterData *outData;

    CryptoMachine(const CryptoMachine &);
    const CryptoMachine &operator=(const CryptoMachine &);

protected:
    Key *getKey() 
    {
        return this->key;
    }

    void setResult(const EncrypterResult *result)
    {
        this->outData = result;
    }

    const EncrypterData *getData() const
    {
        return this->inData;
    }

public:
    CryptoMachine()
    {
        this->key = nullptr;
        this->inData = nullptr;
        this->outData = nullptr;
    }

    virtual ~CryptoMachine()
    {
        delete this->key;
        delete this->inData;
        delete this->outData;

        this->key = nullptr;
        this->inData = nullptr;
        this->outData = nullptr;
    }

    void setKey(Key *key)
    {
        this->key = key;
    }

    virtual void run() = 0;

    void setData(const Byte *in, Size inlen)
    {
        delete this->inData;

        this->inData = new EncrypterData(in, inlen);
    }

    const EncrypterData *getResult() const
    {
        return this->outData;
    }
};

#endif
