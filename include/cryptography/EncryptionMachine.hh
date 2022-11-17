#ifndef ENCRYPTION_MACHINE_HH
#define ENCRYPTION_MACHINE_HH

#include "CryptoMachine.hh"

class EncryptionMachine : public CryptoMachine
{
public:
    void run() override
    {
        Key *key = this->getKey();
        const EncrypterData *data = this->getData();

        this->setResult(key->lock(data));
    }
};

#endif
