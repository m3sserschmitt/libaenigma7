#ifndef SYMMETRIC_EVP_CIPHER_CONTEXT_HH
#define SYMMETRIC_EVP_CIPHER_CONTEXT_HH

#include "EvpCipherContext.hh"

class SymmetricEvpCipherContext : public EvpCipherContext
{
private:
    void encryptionAllocateMemory(const EncrypterData *in)
    {
        this->allocateIV();
        this->allocateOutBuffer(in->getDataSize());
        this->allocateTag();
        this->allocateCipherContext();
    }

    void decryptionAllocateMemory(const EncrypterData *in)
    {
        unsigned int outBufferSize = in->getDataSize() - IV_SIZE - TAG_SIZE;
        this->allocateCipherContext();
        this->allocateIV();
        this->allocateOutBuffer(outBufferSize);
        this->allocateTag();
    }

    /**
     * @brief Create output buffer resulted from a symmetric encryption
     *
     * Structure of output buffer:
     * 1. Initialization Vector (IV);
     * 2. Ciphertext (C)
     * 3. Tag (T)
     *
     * Total size of the output buffer: len(IV) + len(C) + len(T)
     *
     * @return EncrypterResult* structure containing the output buffer resulted from symmetric encryption
     */
    [[nodiscard]] EncrypterResult *createEncryptedData() const;

    /**
     * @brief Read the byte array created by createEncryptedData method an initializes internal structures
     * i.e. initialization vector and tag
     *
     * @param in data to be decrypted, as it was created by createEncryptedData
     * @param cipherLen if successful it contains the size of ciphertext (C)
     * @return const unsigned char * pointer to the ciphertext
     */
    const unsigned char *readEncryptedData(const EncrypterData *in, int &cipherLen);

public:
    explicit SymmetricEvpCipherContext(Key *key) : EvpCipherContext(key) {}

    SymmetricEvpCipherContext(const SymmetricEvpCipherContext &) = delete;
    const SymmetricEvpCipherContext &operator=(const SymmetricEvpCipherContext &) = delete;

    EncrypterResult *encrypt(const EncrypterData *in) override;

    EncrypterResult *decrypt(const EncrypterData *in) override;
};

#endif
