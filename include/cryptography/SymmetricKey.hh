#ifndef SYMMETRIC_KEY_HH
#define SYMMETRIC_KEY_HH

#include "Constants.hh"
#include "Key.hh"

#include <openssl/evp.h>

class SymmetricKey : public Key
{
    Bytes keyData;
    Bytes ivData;
    Bytes tagData;
    Bytes buffer;
    Size bufferSize;

    EVP_CIPHER_CTX *cipherContext;

    SymmetricKey(const SymmetricKey &);
    const SymmetricKey &operator=(const SymmetricKey &);

    void initIV();
    void initCipherContext();
    void initBuffer(Size len);
    void init(Size bufferSize);

    void freeCipherContext();
    void freeBuffer();

    EncrypterResult *abort();

public:
    SymmetricKey() : keyData(new Byte[SYMMETRIC_KEY_SIZE + 1]), ivData(new Byte[IV_SIZE + 1]), tagData(new Byte[TAG_SIZE + 1]), cipherContext(nullptr), buffer(nullptr) {}

    SymmetricKey(const Byte *keyData) : ivData(new Byte[IV_SIZE + 1]), tagData(new Byte[TAG_SIZE + 1]), cipherContext(nullptr), buffer(nullptr)
    {
        this->keyData = new Byte[SYMMETRIC_KEY_SIZE + 1];

        this->setKeyData(keyData);
    }

    ~SymmetricKey()
    {
        memset(this->keyData, 0, SYMMETRIC_KEY_SIZE);
        memset(this->ivData, 0, IV_SIZE);

        delete[] this->keyData;
        delete[] this->ivData;
    }

    void setKeyData(const Byte *keyData)
    {
        memcpy(this->keyData, keyData, SYMMETRIC_KEY_SIZE);
    }

    const EncrypterResult *lock(const EncrypterData *) override;

    const EncrypterResult *unlock(const EncrypterData *) override;
};

#endif
