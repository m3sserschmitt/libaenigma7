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
    //Bytes buffer;
    //Size bufferSize;

    KeyType keyType;
    KeyPassphraseCallback passphraseCallback;

    void init(KeyType keyType)
    {
        //this->setBuffer(nullptr);
        //this->setBufferSize(0);
        this->setKeyType(keyType);
        this->setKeyPassphraseCallback(nullptr);
    }

protected:
    /*Bytes getBuffer()
    {
        return this->buffer;
    }

    void setBuffer(Bytes buffer)
    {
        this->buffer = buffer;
    }

    Size getBufferSize()
    {
        return this->bufferSize;
    }

    void setBufferSize(Size bufferSize)
    {
        this->bufferSize = bufferSize;
    }

    void cleanBuffer()
    {
        Bytes buffer = this->getBuffer();

        if (buffer)
        {
            memset(buffer, 0, this->getBufferSize());
        }
    }

    void freeBuffer()
    {
        this->cleanBuffer();
        delete[] this->getBuffer();
        this->setBuffer(nullptr);
        this->setBufferSize(0);
    }

    void createBuffer(Size size)
    {
        this->freeBuffer();
        this->setBuffer(new Byte[size + 1]);
        this->setBufferSize(size);
    }
*/
public:
    Key() { this->init(UndefinedKey); }

    Key(KeyType keyType) { this->init(keyType); }

    virtual ~Key()
    {
        //this->freeBuffer();
    }

    virtual void setKeyType(KeyType keyType)
    {
        this->keyType = keyType;
    }

    virtual KeyType getKeyType() const
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

    KeyPassphraseCallback getKeyPassphraseCallback() { return this->passphraseCallback; }

    virtual void *getKeyMaterial() = 0;
    /**
     * @brief Perform encryption after successful initialization
     *
     * @return const EncrypterResult* Structure containing encrypted buffer, size and error flag
     */
    //virtual const EncrypterResult *lock(const EncrypterData *) = 0;

    /**
     * @brief Perform decryption after successful initialization
     *
     * @return const EncrypterResult* Structure containing decrypted buffer, size and error flag
     */
    //virtual const EncrypterResult *unlock(const EncrypterData *) = 0;

    //virtual void reset()
    //{
        //this->freeBuffer();
    //}
};

#endif
