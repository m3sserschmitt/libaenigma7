#ifndef CIPHER_CONTEXT_HH
#define CIPHER_CONTEXT_HH

#include "Cipher.hh"

class SymmetricCipher : Cipher
{
    SymmetricCipher(const SymmetricCipher &);
    const SymmetricCipher &operator=(const SymmetricCipher &);
    
    Bytes getKeyData() { return (Bytes)this->getKey()->getKeyMaterial(); }

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
    SymmetricCipher(Key *key) : Cipher(key) {}

    EncrypterResult *encrypt(const EncrypterData *in) override;

    EncrypterResult *decrypt(const EncrypterData *in) override;

    static Cipher *create(Key *key) { return new SymmetricCipher(key); }
};

#endif
