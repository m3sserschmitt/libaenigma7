#ifndef DECRYPTION_RESULT_HH
#define DECRYPTION_RESULT_HH

#include "CryptoMachine.hh"

class DecryptionMachine : public CryptoMachine
{
public:
    void run() override
    {
        Key *key = this->getKey();
        const EncrypterData *data = this->getData();

        this->setResult(key->unlock(data));
    }
};

#endif
