#ifndef DECRYPTION_RESULT_HH
#define DECRYPTION_RESULT_HH

#include "CryptoMachine.hh"

class DecryptionMachine : public CryptoMachine
{
public:
    DecryptionMachine(Cipher *cipher) : CryptoMachine(cipher) {}

    void run() override
    {
        this->setOut(this->getCipher()->decrypt(this->getIn()));
    }

    static CryptoMachine *create(Cipher *cipher)
    {
        return new DecryptionMachine(cipher);
    }
};

#endif
