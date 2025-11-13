#ifndef CRYPTO_MACHINE_HH
#define CRYPTO_MACHINE_HH

#include "EvpContext.hh"

class CryptoMachine
{
private:
    EvpContext *cipher;

    const EncrypterData *in;
    const EncrypterResult *out;

    void setIn(const EncrypterData *inData) { this->in = inData; }

    void freeIn()
    {
        delete this->getIn();
        this->setIn(nullptr);
    }

protected:
    void freeOut()
    {
        delete this->getOut();
        this->setOut(nullptr);
    }

    [[nodiscard]] const EncrypterData *getIn() const { return this->in; }

    void setOut(const EncrypterResult *outData) { this->out = outData; }

    [[nodiscard]] const EncrypterResult *getOut() const { return this->out; }

    EvpContext *getCipher() { return this->cipher; }

public:
    explicit CryptoMachine(EvpContext *c)
    {
        this->in = nullptr;
        this->out = nullptr;
        this->cipher = c;
    }

    CryptoMachine(const CryptoMachine &) = delete;
    const CryptoMachine &operator=(const CryptoMachine &) = delete;

    virtual ~CryptoMachine()
    {
        this->freeIn();
        this->freeOut();
    }

    virtual bool run() = 0;

    void setInput(const unsigned char *data, unsigned int dataLen)
    {
        this->freeIn();
        this->setIn(new EncrypterData(data, dataLen));
    }

    [[nodiscard]] const EncrypterResult *getOutput() const { return this->out; }
};

#endif
