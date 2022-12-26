#ifndef ENCRYPTION_MACHINE_HH
#define ENCRYPTION_MACHINE_HH

#include "CryptoMachine.hh"

class EncryptionMachine : public CryptoMachine
{
public:
    EncryptionMachine(Cipher *cipher) : CryptoMachine(cipher) {}

    void run() override
    {
        this->setOut(this->getCipher()->encrypt(this->getIn()));
    }

    static CryptoMachine *create(Cipher *cipher)
    {
        return new EncryptionMachine(cipher);
    }
};

#endif
