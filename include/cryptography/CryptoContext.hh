#ifndef CRYPTO_CONTEXT_HH
#define CRYPTO_CONTEXT_HH

#include "EncryptionMachine.hh"
#include "DecryptionMachine.hh"
#include "SymmetricKey.hh"

enum CryptoType
{
    SymmetricCryptography,
    AsymmetricCryptography
};

enum CryptoOp
{
    Encrypt,
    Decrypt
};

class CryptoContext
{
    CryptoType cryptoType;
    CryptoOp cryptoOp;

    Key *key;
    CryptoMachine *cryptoMachine;

    CryptoContext(const CryptoContext &);
    const CryptoContext &operator=(const CryptoContext &);

    void initKey(CryptoType cryptoType, CryptoOp cryptoOp)
    {
        this->cryptoType = cryptoType;

        delete this->key;

        this->cryptoType == SymmetricCryptography and (this->key = SymmetricKey::create());

        if (this->cryptoMachine)
        {
            this->cryptoMachine->setKey(this->key);
        }
    }

    void initCryptoMachine(CryptoOp cryptoOp)
    {
        this->cryptoOp = cryptoOp;

        delete this->cryptoMachine;

        this->cryptoOp == Decrypt and (this->cryptoMachine = new DecryptionMachine());
        this->cryptoOp == Encrypt and (this->cryptoMachine = new EncryptionMachine());

        this->cryptoMachine->setKey(this->key);
    }

public:
    CryptoContext(CryptoType cryptoType, CryptoOp cryptoOp)
    {
        this->init(cryptoType, cryptoOp);
    }

    ~CryptoContext()
    {
        delete this->key;
        delete this->cryptoMachine;
    }

    void init(CryptoType cryptoType, CryptoOp cryptoOp)
    {
        this->initKey(cryptoType, cryptoOp);
        this->initCryptoMachine(cryptoOp);
    }

    CryptoOp getCryptoOp() const
    {
        return this->cryptoOp;
    }

    CryptoType getCryptoType() const
    {
        return this->cryptoType;
    }

    void setKey(const Byte *key, Size keylen)
    {
        if (this->key)
        {
            this->key->setKeyData(key, keylen);
        }
    }

    void setPlaintext(const Byte *data, Size datalen)
    {
        if (this->cryptoMachine and this->cryptoOp == Encrypt)
        {
            this->cryptoMachine->setInput(data, datalen);
        }
    }

    const EncrypterData *getPlaintext() const
    {
        if(this->cryptoMachine and this->cryptoOp == Decrypt)
        {
            return this->cryptoMachine->getOutput();
        }

        return nullptr;
    }

    void setCiphertext(const Byte *data, Size datalen)
    {
        if(this->cryptoMachine and this->cryptoOp == Decrypt)
        {
            this->cryptoMachine->setInput(data, datalen);
        }
    }

    const EncrypterData *getCiphertext() const
    {
        if (this->cryptoMachine and this->cryptoOp == Encrypt)
        {
            return this->cryptoMachine->getOutput();
        }

        return nullptr;
    }

    void run()
    {
        if (this->cryptoMachine)
        {
            this->cryptoMachine->run();
        }
    }

    /*void reset()
    {
        if (this->key)
        {
            this->key->reset();
        }
    }*/
};

#endif