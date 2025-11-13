#ifndef ASYMMETRIC_CIPHER_HH
#define ASYMMETRIC_CIPHER_HH

#include "EvpCipherContext.hh"

class AsymmetricEvpCipherContext : public EvpCipherContext
{
private:
    unsigned char *encryptedKey;
    int encryptedKeyLength;

    void freeEncryptedKey()
    {
        if (this->encryptedKey)
        {
            memset(encryptedKey, 0, SYMMETRIC_KEY_SIZE);
            delete[] encryptedKey;
            this->encryptedKey = nullptr;
            this->encryptedKeyLength = 0;
        }
    }

    bool allocateEncryptedKey()
    {
        int pKeySize = this->getKeySize();

        if (pKeySize <= 0)
        {
            return false;
        }

        this->freeEncryptedKey();
        this->encryptedKey = new unsigned char[pKeySize + 1];
        this->encryptedKeyLength = 0;

        return true;
    }

    bool writeEncryptedKey(const unsigned char *key)
    {
        if (key and this->encryptedKey)
        {
            int encryptedKeySize = this->getKeySize();
            memcpy(this->encryptedKey, key, encryptedKeySize);
            this->encryptedKeyLength = encryptedKeySize;
            return true;
        }

        return false;
    }

    void sealEnvelopeAllocateMemory(const EncrypterData *in)
    {
        this->allocateCipherContext();
        this->allocateEncryptedKey();
        this->allocateIV();
        this->allocateOutBuffer(in->getDataSize());
        this->allocateTag();
    }

    void openEnvelopeAllocateMemory(const EncrypterData *in)
    {
        unsigned int outBufferSize = in->getDataSize() - this->getKeySize() - IV_SIZE - TAG_SIZE;
        this->allocateCipherContext();
        this->allocateEncryptedKey();
        this->allocateIV();
        this->allocateOutBuffer(outBufferSize);
        this->allocateTag();
    }

    [[nodiscard]] unsigned int calculateEnvelopeSize() const
    {
        return this->encryptedKeyLength + IV_SIZE + this->getOutBufferSize() + TAG_SIZE;
    }

    /**
     * @brief Create an Envelope;
     *
     * Envelope structure:
     * N = size of public key in bytes (e.g. 2048 bits key length => N = 256 bytes) = len(EK);
     *
     * Structure of envelope:
     * 1. Encrypted Key (EK);
     * 2. Initialization Vector (IV); AES GCM default IV length is 12 bytes;
     * 3. Ciphertext (C); note: length of ciphertext is equal to length of plaintext when using GCM;
     * 4. Tag (T); AES GCM default tag size is 16 bytes;
     *
     * Envelope total size: N + len(IV) + len(C) + len(T)
     *
     * @return EncrypterResult* Structure containing envelope data and size;
     */
    [[nodiscard]] EncrypterResult *createEnvelope() const;

    /**
     * @brief Read a byte array created by createEnvelope method and initializes internal structures
     * i.e. initialization vector (IV), encrypted key (EK) and tag (T)
     *
     * @param in Structure containing envelope data and size
     * @param cipherLen if successful it contains the calculated size of ciphertext (C)
     * @return const unsigned char * pointer to the ciphertext (C)
     */
    const unsigned char *readEnvelope(const EncrypterData *in, int &cipherLen);

public:
    explicit AsymmetricEvpCipherContext(Key *key) : EvpCipherContext(key)
    {
        this->encryptedKey = nullptr;
        this->encryptedKeyLength = 0;
    }

    ~AsymmetricEvpCipherContext() override { this->freeEncryptedKey(); }

    AsymmetricEvpCipherContext(const AsymmetricEvpCipherContext &) = delete;

    const AsymmetricEvpCipherContext *operator=(const AsymmetricEvpCipherContext &) = delete;

    EncrypterResult *encrypt(const EncrypterData *in) override;

    EncrypterResult *decrypt(const EncrypterData *in) override;

    void cleanup() override
    {
        EvpCipherContext::cleanup();
        this->freeEncryptedKey();
    }
};

#endif
