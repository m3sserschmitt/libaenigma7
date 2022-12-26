#ifndef ASYMMETRIC_CIPHER_HH
#define ASYMMETRIC_CIPHER_HH

#include "Cipher.hh"
#include "AsymmetricKey.hh"

class AsymmetricCipher : Cipher
{
    Bytes encryptedKey;
    int encryptedKeyLength;

    EVP_PKEY *getPkey() { return (EVP_PKEY *)this->getKey()->getKeyMaterial(); }

    int getPkeySize()
    {
        EVP_PKEY *pkey = this->getPkey();

        if (pkey)
        {
            return EVP_PKEY_size(pkey);
        }

        return -1;
    }

    void setEncryptedKey(Bytes encryptedKey) { this->encryptedKey = encryptedKey; }

    void setEncryptedKeyLength(Size len) { this->encryptedKeyLength = len; }

    Size getEncryptedKeyLength() const { return this->encryptedKeyLength; }

    Bytes getEncryptedKey() { return this->encryptedKey; }

    int *getEncryptedKeyLengthPtr() { return &this->encryptedKeyLength; }

    unsigned char **getEncryptedKeyPtr() { return &this->encryptedKey; }

    void freeEncryptedKey()
    {
        Bytes encryptedKey = this->getEncryptedKey();

        if (encryptedKey)
        {
            memset(encryptedKey, 0, SYMMETRIC_KEY_SIZE);
            delete[] encryptedKey;
            this->setEncryptedKey(nullptr);
            this->setEncryptedKeyLength(0);
        }
    }

    bool allocateEncryptedKey()
    {
        int pkeySize = this->getPkeySize();

        if (pkeySize < 0)
        {
            return false;
        }

        this->freeEncryptedKey();
        this->setEncryptedKey(new Byte[pkeySize + 1]);
        this->setEncryptedKeyLength(0);

        return this->getEncryptedKey() != nullptr;
    }

    bool writeEncryptedKey(ConstBytes encryptedKey)
    {
        Bytes localEncryptedKey = this->getEncryptedKey();

        if (encryptedKey and localEncryptedKey)
        {
            Size encryptedKeySize = this->getPkeySize();
            memcpy(localEncryptedKey, encryptedKey, encryptedKeySize);
            this->setEncryptedKeyLength(encryptedKeySize);
            return true;
        }

        return false;
    }

    bool sealEnvelopeAllocateMemory(const EncrypterData *in)
    {
        return this->allocateCipherContext() and this->allocateEncryptedKey() and this->allocateIV() and this->allocateOutBuffer(in->getDataSize()) and this->allocateTag();
    }

    bool openEnvelopeAllocateMemory(const EncrypterData *in)
    {
        Size outBufferSize = in->getDataSize() - this->getPkeySize() - IV_SIZE - TAG_SIZE;
        return this->allocateCipherContext() and this->allocateEncryptedKey() and this->allocateIV() and this->allocateOutBuffer(outBufferSize) and this->allocateTag();
    }

    Size calculateEnvelopeSize()
    {
        Size encryptedKeySize = this->getEncryptedKeyLength();
        Size outBufferSize = this->getOutBufferSize();

        return encryptedKeySize + IV_SIZE + outBufferSize + TAG_SIZE;
    }

    /**
     * @brief Create a Envelope;
     *
     * Envelope structure:
     * N = size of public key (e.g. 2048 bits key length => N = 256 bytes);
     * P = size of plaintext;
     *
     * Encrypted Key: bytes 0..N-1;
     * Initialization Vector: bytes N..N+11 (AES GCM default IV length of 12 bytes);
     * Encrypted buffer: bytes N+12..N+P+11;
     * Tag: bytes N+P+11..N+P+26 (AES GCM tag size of 16 bytes);
     * @return EncrypterResult* Structure containing envelope data and size;
     */
    EncrypterResult *createEnvelope()
    {
        Size envelopeSize = this->calculateEnvelopeSize();
        Bytes envelope = new Byte[envelopeSize + 1];

        Size N = this->getEncryptedKeyLength();
        Size P = this->getOutBufferSize();

        memcpy(envelope, this->getEncryptedKey(), N);
        memcpy(envelope + N, this->getIV(), IV_SIZE);
        memcpy(envelope + N + IV_SIZE, this->getOutBuffer(), P);
        memcpy(envelope + N + IV_SIZE + P, this->getTag(), TAG_SIZE);

        EncrypterResult *result = new EncrypterResult(envelope, envelopeSize);

        memset(envelope, 0, envelopeSize);
        delete[] envelope;

        return result;
    }

    ConstBytes readEnvelope(const EncrypterData *in, Size &cipherlen)
    {
        cipherlen = 0;

        if (not in or not in->getData())
        {
            return nullptr;
        }

        Size N = this->getPkeySize();
        Size envelopeSize = in->getDataSize();
        ConstBytes envelope = in->getData();

        if (not this->writeEncryptedKey(envelope) or not this->writeIV(envelope + N) or not this->writeTag(envelope + envelopeSize - TAG_SIZE))
        {
            return nullptr;
        }

        cipherlen = envelopeSize - N - IV_SIZE - TAG_SIZE;
        return envelope + N + IV_SIZE;
    }

    void reset() override
    {
        Cipher::reset();
        this->freeEncryptedKey();
    }

    void init()
    {
        this->setEncryptedKey(nullptr);
        this->setEncryptedKeyLength(0);
    }

public:
    AsymmetricCipher(Key *key) : Cipher(key)
    {
        this->init();
    }

    EncrypterResult *encrypt(const EncrypterData *in) override
    {
        if (not in or not in->getData())
        {
            return this->abort();
        }

        this->reset();

        if (not this->sealEnvelopeAllocateMemory(in))
        {
            return this->abort();
        }

        EVP_PKEY *pkey = this->getPkey();

        if (EVP_SealInit(this->getCipherContext(),
                         EVP_aes_256_gcm(),
                         this->getEncryptedKeyPtr(),
                         this->getEncryptedKeyLengthPtr(),
                         this->getIV(),
                         &pkey, 1) != 1)
        {
            return this->abort();
        }

        int len;
        int len2;

        if (EVP_SealUpdate(this->getCipherContext(), this->getOutBuffer(), &len, in->getData(), in->getDataSize()) != 1)
        {
            return this->abort();
        }

        if (EVP_SealFinal(this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
        {
            return this->abort();
        }

        if (EVP_CIPHER_CTX_ctrl(this->getCipherContext(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, this->getTag()) != 1)
        {
            return this->abort();
        }

        this->setOutBufferSize(len + len2);

        EncrypterResult *result = this->createEnvelope();

        this->reset();

        return result;
    }

    EncrypterResult *decrypt(const EncrypterData *in) override
    {
        if (not in or not in->getData())
        {
            return this->abort();
        }

        this->reset();

        if (not this->openEnvelopeAllocateMemory(in))
        {
            return this->abort();
        }

        Size cipherlen;
        ConstBytes ciphertext = this->readEnvelope(in, cipherlen);

        if (not ciphertext or not cipherlen)
        {
            return this->abort();
        }

        if (EVP_OpenInit(this->getCipherContext(),
                         EVP_aes_256_gcm(),
                         this->getEncryptedKey(),
                         this->getEncryptedKeyLength(),
                         this->getIV(),
                         this->getPkey()) != 1)
        {
            return this->abort();
        }

        int len;

        if (EVP_OpenUpdate(this->getCipherContext(),
                           this->getOutBuffer(),
                           &len, ciphertext, cipherlen) != 1)
        {
            return this->abort();
        }

        if (EVP_CIPHER_CTX_ctrl(this->getCipherContext(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, this->getTag()) != 1)
        {
            return this->abort();
        }

        int len2;

        if (EVP_OpenFinal(this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
        {
            return this->abort();
        }

        this->setOutBufferSize(len + len2);

        EncrypterResult *result = new EncrypterResult(this->getOutBuffer(), this->getOutBufferSize());

        this->reset();

        return result;
    }

    static Cipher *create(Key *key) { return new AsymmetricCipher(key); }
};

#endif
