#ifndef SYMMETRIC_KEY_HH
#define SYMMETRIC_KEY_HH

#include "RandomDataGenerator.hh"
#include "Constants.hh"
#include "Key.hh"

#include <openssl/evp.h>

class SymmetricKey : public Key
{
    Bytes keyData;
    Bytes ivData;
    Bytes tagData;

    EVP_CIPHER_CTX *cipherContext;

    SymmetricKey(const SymmetricKey &);
    const SymmetricKey &operator=(const SymmetricKey &);

    void initIV()
    {
        EncrypterData *randomData = RandomDataGenerator::generate(IV_SIZE);
        memcpy(this->ivData, randomData->getData(), IV_SIZE);

        delete randomData;
    }

    void initIV(const Byte *ivData)
    {
        memcpy(this->ivData, ivData, IV_SIZE);
    }

    void initTagData(const Byte *tagData)
    {
        memcpy(this->tagData, tagData, TAG_SIZE);
    }

    void createCipherContext()
    {
        this->freeCipherContext();

        this->cipherContext = EVP_CIPHER_CTX_new();
    }

    void initEncryption(Size bufferSize)
    {
        this->createBuffer(bufferSize);
        this->initIV();
        this->createCipherContext();
    }

    void initDecryption(const EncrypterData *data);

    void freeCipherContext()
    {
        if (this->cipherContext)
        {
            EVP_CIPHER_CTX_free(cipherContext);
            this->cipherContext = nullptr;
        }
    }

    EncrypterResult *abort()
    {
        this->freeCipherContext();
        this->freeBuffer();

        return new EncrypterResult(false);
    }

    EncrypterResult *prepareEncryptedBuffer();

public:
    SymmetricKey() : Key(),
                     keyData(new Byte[SYMMETRIC_KEY_SIZE + 1]),
                     ivData(new Byte[IV_SIZE + 1]),
                     tagData(new Byte[TAG_SIZE + 1]),
                     cipherContext(nullptr) {}

    SymmetricKey(const Byte *keyData) : Key(),
                                        ivData(new Byte[IV_SIZE + 1]),
                                        tagData(new Byte[TAG_SIZE + 1]),
                                        cipherContext(nullptr)
    {
        this->keyData = new Byte[SYMMETRIC_KEY_SIZE + 1];

        this->setKeyData(keyData, SYMMETRIC_KEY_SIZE);
    }

    ~SymmetricKey()
    {
        memset(this->keyData, 0, SYMMETRIC_KEY_SIZE);
        memset(this->ivData, 0, IV_SIZE);
        memset(this->tagData, 0, TAG_SIZE);

        delete[] this->keyData;
        delete[] this->ivData;
        delete[] this->tagData;

        this->keyData = nullptr;
        this->ivData = nullptr;
        this->tagData = nullptr;
    }

    void setKeyData(const Byte *keyData, Size keylen) override
    {
        memcpy(this->keyData, keyData, keylen);
    }

    void reset() override
    {
        Key::reset();
        memset(this->ivData, 0, IV_SIZE);
        memset(this->tagData, 0, TAG_SIZE);
    }

    const EncrypterResult *lock(const EncrypterData *) override;

    const EncrypterResult *unlock(const EncrypterData *) override;

    static Key *create(const Byte *keyData)
    {
        return new SymmetricKey(keyData);
    }

    static Key *create()
    {
        return new SymmetricKey();
    }
};

#endif
