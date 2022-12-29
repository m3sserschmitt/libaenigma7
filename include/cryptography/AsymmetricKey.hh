#ifndef ASYMMETRIC_KEY_HH
#define ASYMMETRIC_KEY_HH

#include "Key.hh"
#include "exceptions/InvalidKey.hh"

#include <openssl/pem.h>

class AsymmetricKey : public Key
{
    EVP_PKEY *key;

    AsymmetricKey(const AsymmetricKey &);
    const AsymmetricKey &operator=(const AsymmetricKey &);

    void init() { this->setPkey(nullptr); }

    const EVP_PKEY *getPkey() const { return this->key; }

    EVP_PKEY *getPkey() { return this->key; }

    void setPkey(EVP_PKEY *key) { this->key = key; }

    void freeKey()
    {
        EVP_PKEY_free(this->getPkey());
        this->setPkey(nullptr);
    }

    bool notNullPkey() const { return this->key != nullptr; }

    static bool validate(KeyType keyType) { return keyType == PublicKey or keyType == PrivateKey or keyType == UndefinedKey; }

public:
    AsymmetricKey(KeyType keyType) : Key(keyType)
    {
        if (not AsymmetricKey::validate(keyType))
        {
            throw InvalidKey("Invalid Key Type used for object initialization");
        }

        this->init();
    }

    void setKeyType(KeyType keyType) override
    {
        if (not AsymmetricKey::validate(keyType))
        {
            throw InvalidKey("Invalid Key Type");
        }

        this->freeKey();
        Key::setKeyType(keyType);
    }

    bool setKeyData(ConstBytes keyData, Size len, Plaintext passphrase = nullptr) override;

    bool readKeyFile(ConstPlaintext path, Plaintext passphrase = nullptr) override;

    const void *getKeyMaterial() const override { return this->getPkey(); }

    static Key *create(KeyType keyType)
    {
        return new AsymmetricKey(keyType);
    }
};

#endif
