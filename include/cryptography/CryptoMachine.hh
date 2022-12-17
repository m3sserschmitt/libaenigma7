#ifndef CRYPTO_MACHINE_HH
#define CRYPTO_MACHINE_HH

#include "Key.hh"
#include "EncrypterResult.hh"

class CryptoMachine
{
    Key *key;

    const EncrypterData *in;
    const EncrypterData *out;

    CryptoMachine(const CryptoMachine &);
    const CryptoMachine &operator=(const CryptoMachine &);

protected:
    

    const EncrypterData *getIn() const
    {
        return this->in;
    }

    void setOut(const EncrypterData *out)
    {
        this->out = out;
    }

    const EncrypterData *getOut() const
    {
        return this->out;
    }

public:
    CryptoMachine()
    {
        this->key = nullptr;
        this->in = nullptr;
        this->out = nullptr;
    }

    virtual ~CryptoMachine()
    {
        delete this->in;
        delete this->out;

        this->in = nullptr;
        this->out = nullptr;
    }

    Key *getKey() 
    {
        return this->key;
    }

    void setKey(Key *key)
    {
        this->key = key;
    }

    virtual void run() = 0;

    void setInput(const Byte *data, Size datalen)
    {
        delete this->in;

        this->in = new EncrypterData(data, datalen);
    }

    const EncrypterData *getOutput() const
    {
        return this->out;
    }
};

#endif
