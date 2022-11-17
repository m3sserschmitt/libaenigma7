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
    void initIV(const Byte *ivData);
    void initTagData(const Byte *tagData)
    {
        memcpy(this->tagData, tagData, TAG_SIZE);
    }
    void createCipherContext();
    void createBuffer(Size len);

    void initEncryption(Size bufferSize);
    void initDecryption(const EncrypterData *data);

    void freeCipherContext();
    void freeBuffer();

    EncrypterResult *abort();

    EncrypterResult *prepareEncryptedBuffer();

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
        memset(this->tagData, 0, TAG_SIZE);

        if(this->buffer)
        {
            memset(this->buffer, 0, this->bufferSize);
            delete[] this->buffer;
            this->buffer = nullptr;
        }

        delete[] this->keyData;
        delete[] this->ivData;
        delete[] this->tagData;

        this->keyData = nullptr;
        this->ivData = nullptr;
        this->tagData = nullptr;
    }

    void setKeyData(const Byte *keyData)
    {
        memcpy(this->keyData, keyData, SYMMETRIC_KEY_SIZE);
    }

    const EncrypterResult *lock(const EncrypterData *) override;

    const EncrypterResult *unlock(const EncrypterData *) override;
};

#endif
