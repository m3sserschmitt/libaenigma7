#ifndef DECRYPTION_RESULT_HH
#define DECRYPTION_RESULT_HH

#include "CryptoMachine.hh"

class DecryptionMachine : public CryptoMachine
{
    DecryptionMachine(const DecryptionMachine &);
    const DecryptionMachine &operator=(const DecryptionMachine &);

public:
    DecryptionMachine(Cipher *cipher) : CryptoMachine(cipher) {}

    bool run() override
    {
        EncrypterResult *result = this->getCipher()->decrypt(this->getIn());
        this->setOut(result);
        return not result->isError();
    }

    static CryptoMachine *create(Cipher *cipher)
    {
        return new DecryptionMachine(cipher);
    }
};

#endif
