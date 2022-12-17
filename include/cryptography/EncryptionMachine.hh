#ifndef ENCRYPTION_MACHINE_HH
#define ENCRYPTION_MACHINE_HH

#include "CryptoMachine.hh"

class EncryptionMachine : public CryptoMachine
{
public:
    void run() override
    {
        Key *key = this->getKey();
        const EncrypterData *data = this->getIn();

        this->setOut(key->lock(data));
    }

    static CryptoMachine *create()
    {
        return new EncryptionMachine();
    }
};

#endif
