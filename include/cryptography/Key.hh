#ifndef KEY_HH
#define KEY_HH

#include "EncrypterData.hh"
#include "EncrypterResult.hh"
#include "File.hh"

enum KeyType
{
    KeySymmetric,
    PublicKey,
    PrivateKey,
    UndefinedKey
};

typedef int (*KeyPassphraseCallback)(char *buf, int size, int rwflag, void *u);

class Key
{
    KeyType keyType;
    KeyPassphraseCallback passphraseCallback;

    void init(KeyType keyType)
    {
        this->setKeyType(keyType);
        this->setKeyPassphraseCallback(nullptr);
    }

protected:

    virtual void setKeyType(KeyType keyType)
    {
        this->keyType = keyType;
    }

public:
    Key() { this->init(UndefinedKey); }

    Key(KeyType keyType) { this->init(keyType); }

    virtual ~Key() {}

    KeyType getKeyType() const
    {
        return this->keyType;
    }

    bool isPublicKey() const
    {
        return this->getKeyType() == PublicKey;
    }

    bool isPrivateKey() const
    {
        return this->getKeyType() == PrivateKey;
    }

    bool isSymmetricKey() const
    {
        return this->getKeyType() == KeySymmetric;
    }

    /**
     * @brief Initialize encryption / decryption key from buffer. This method should be overriden into any derived class
     * to achieve desired behavior.
     *
     * @param keyData Key material for initialization
     * @param len Size initialization buffer
     * @param passphrase Passphrase for key file decryption (usually for reading private keys)
     * @return true If initialization successful
     * @return false If initialization failed
     */
    virtual bool setKeyData(ConstBytes keyData, Size len, Plaintext passphrase = nullptr) = 0;

    /**
     * @brief Read encryption / decryption key material from file (especially useful for public/private key pairs). Override
     * this method into any derived class to achieve desired behavior
     *
     * @param path Path to file which contains key material for initialization
     * @param passphrase Passphrase for key file decryption (usually for reading private keys)
     * @return true If initialization successful
     * @return false If initialization failed
     */
    virtual bool readKeyFile(ConstPlaintext path, Plaintext passphrase = nullptr) = 0;

    void setKeyPassphraseCallback(KeyPassphraseCallback passphraseCallback) { this->passphraseCallback = passphraseCallback; }

    const KeyPassphraseCallback getKeyPassphraseCallback() const { return this->passphraseCallback; }

    virtual const void *getKeyMaterial() const = 0;
};

#endif
