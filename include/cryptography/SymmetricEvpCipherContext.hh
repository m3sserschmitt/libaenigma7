#ifndef SYMMETRIC_EVP_CIPHER_CONTEXT_HH
#define SYMMETRIC_EVP_CIPHER_CONTEXT_HH

#include "EvpCipherContext.hh"

class SymmetricEvpCipherContext : public EvpCipherContext
{
    SymmetricEvpCipherContext(const SymmetricEvpCipherContext &);
    const SymmetricEvpCipherContext &operator=(const SymmetricEvpCipherContext &);

    Bytes getKeyBytes() { return (Bytes)this->getKey()->getKeyMaterial(); }

    bool encryptionAllocateMemory(const EncrypterData *in)
    {
        return this->allocateCipherContext() and this->allocateIV() and this->allocateOutBuffer(in->getDataSize()) and this->allocateTag();
    }

    bool decryptionAllocateMemory(const EncrypterData *in)
    {
        Size outBufferSize = in->getDataSize() - IV_SIZE - TAG_SIZE;
        return this->allocateCipherContext() and this->allocateIV() and this->allocateOutBuffer(outBufferSize) and this->allocateTag();
    }

    EncrypterResult *createEncryptedData() const;

    ConstBytes readEncryptedData(const EncrypterData *in, Size &cipherlen);

public:
    SymmetricEvpCipherContext(Key *key) : EvpCipherContext(key) {}

    ~SymmetricEvpCipherContext() {}

    EncrypterResult *encrypt(const EncrypterData *in) override;

    EncrypterResult *decrypt(const EncrypterData *in) override;

    static EvpContext *create(Key *key) { return new SymmetricEvpCipherContext(key); }
};

#endif
