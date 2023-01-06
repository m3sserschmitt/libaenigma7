#ifndef CRYPTO_MACHINE_HH
#define CRYPTO_MACHINE_HH

#include "EvpContext.hh"

class CryptoMachine
{
    EvpContext *cipher;

    const EncrypterData *in;
    const EncrypterData *out;

    CryptoMachine(const CryptoMachine &);
    const CryptoMachine &operator=(const CryptoMachine &);

    void setIn(const EncrypterData *in)
    {
        this->in = in;
    }

    void freeIn()
    {
        delete this->getIn();
        this->setIn(nullptr);
    }

    void freeOut()
    {
        delete this->getOut();
        this->setOut(nullptr);
    }

    void setCipher(EvpContext *cipher)
    {
        this->cipher = cipher;
    }

    void init(EvpContext *cipher)
    {
        this->setIn(nullptr);
        this->setOut(nullptr);
        this->setCipher(cipher);
    }

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

    bool notNullIn() const { return this->in != nullptr; }

    EvpContext *getCipher() { return this->cipher; }

public:
    CryptoMachine(EvpContext *cipher)
    {
        this->init(cipher);
    }

    virtual ~CryptoMachine()
    {
        this->freeIn();
        this->freeOut();
    }

    virtual bool run() = 0;

    bool setInput(ConstBytes data, Size datalen)
    {
        this->freeIn();
        this->setIn(new EncrypterData(data, datalen));
        return this->notNullIn();
    }

    const EncrypterData *getOutput() const
    {
        return this->out;
    }
};

#endif
