#ifndef ENCRYPTION_MACHINE_HH
#define ENCRYPTION_MACHINE_HH

#include "CryptoMachine.hh"

class EncryptionMachine : public CryptoMachine
{
public:
    explicit EncryptionMachine(EvpContext *cipher) : CryptoMachine(cipher) {}

    EncryptionMachine(const EncryptionMachine &) = delete;
    const EncryptionMachine &operator=(const EncryptionMachine &) = delete;

    bool run() override
    {
        if (!this->getCipher() || !this->getIn())
        {
            return false;
        }
        EncrypterResult *result = this->getCipher()->encrypt(this->getIn());
        this->freeOut();
        this->setOut(result);
        return not result->isError();
    }

    static CryptoMachine *create(EvpContext *cipher) { return new EncryptionMachine(cipher); }
};

#endif
