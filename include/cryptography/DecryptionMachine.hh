#ifndef DECRYPTION_RESULT_HH
#define DECRYPTION_RESULT_HH

#include "CryptoMachine.hh"

class DecryptionMachine : public CryptoMachine
{
public:
    void run() override
    {
        Key *key = this->getKey();
        const EncrypterData *data = this->getIn();

        this->setOut(key->unlock(data));
    }

    static CryptoMachine *create()
    {
        return new DecryptionMachine();
    }
};

#endif
