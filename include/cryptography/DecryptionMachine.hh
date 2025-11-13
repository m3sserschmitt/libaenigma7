#ifndef DECRYPTION_RESULT_HH
#define DECRYPTION_RESULT_HH

#include "CryptoMachine.hh"

class DecryptionMachine : public CryptoMachine
{
public:
    explicit DecryptionMachine(EvpContext *cipher) : CryptoMachine(cipher) {}

    DecryptionMachine(const DecryptionMachine &) = delete;
    const DecryptionMachine &operator=(const DecryptionMachine &) = delete;

    bool run() override
    {
        if (this->getCipher() == nullptr || this->getIn() == nullptr)
        {
            return false;
        }
        EncrypterResult *result = this->getCipher()->decrypt(this->getIn());
        this->freeOut();
        this->setOut(result);
        return not result->isError();
    }

    static CryptoMachine *create(EvpContext *cipher) { return new DecryptionMachine(cipher); }
};

#endif
