#ifndef CRYPTO_MACHINE_HH
#define CRYPTO_MACHINE_HH

#include "Key.hh"
#include "Cipher.hh"
#include "EncrypterResult.hh"

class CryptoMachine
{
    Cipher *cipher;

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

    void setCipher(Cipher *cipher)
    {
        this->cipher = cipher;
    }

    void init(Cipher *cipher)
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

    Cipher *getCipher() { return this->cipher; }

public:
    CryptoMachine(Cipher *cipher)
    {
        this->init(cipher);
    }

    virtual ~CryptoMachine()
    {
        this->freeIn();
        this->freeOut();
    }

    virtual void run() = 0;

    void setInput(ConstBytes data, Size datalen)
    {
        this->freeIn();
        this->setIn(new EncrypterData(data, datalen));
    }

    const EncrypterData *getOutput() const
    {
        return this->out;
    }
};

#endif
