#ifndef CRYPTO_CONTEXT_HH
#define CRYPTO_CONTEXT_HH

#include "EncryptionMachine.hh"
#include "DecryptionMachine.hh"
#include "SymmetricKey.hh"
#include "AsymmetricKey.hh"

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

    void setCryptoType(CryptoType cryptoType) { this->cryptoType = cryptoType; }

    void setCryptoOp(CryptoOp cryptoOp) { this->cryptoOp = cryptoOp; }

    void setKey(Key *key) { this->key = key; }

    Key *getKey() { return this->key; }

    void setCryptoMachine(CryptoMachine *cryptoMachine) { this->cryptoMachine = cryptoMachine; }

    CryptoMachine *getCryptoMachine() { return this->cryptoMachine; }

    const CryptoMachine *getCryptoMachine() const { return this->cryptoMachine; }

    bool cryptoMachineSet() const { return this->cryptoMachine != nullptr; }

    bool keySet() const { return this->key != nullptr; }

    void freeKey()
    {
        delete this->getKey();
        this->setKey(nullptr);
    }

    bool allocateKey()
    {
        switch (this->getCryptoType())
        {
        case SymmetricCryptography:
            this->setKey(SymmetricKey::create());
            break;
        case AsymmetricCryptography:
            switch (this->getCryptoOp())
            {
            case Encrypt:
                this->setKey(AsymmetricKey::create(PublicKey));
                break;
            case Decrypt:
                this->setKey(AsymmetricKey::create(PrivateKey));
                break;
            default:
                return false;
            }
            break;
        default:
            return false;
        }

        return this->keySet();
    }

    void cryptoMachineAssignKey()
    {
        if (this->cryptoMachineSet())
        {
            this->getCryptoMachine()->setKey(this->getKey());
        }
    }

    bool initKey(CryptoType cryptoType, CryptoOp cryptoOp)
    {
        this->setCryptoType(cryptoType);
        this->setCryptoOp(cryptoOp);

        this->freeKey();
        bool ok = this->allocateKey();

        this->cryptoMachineAssignKey();

        return ok;
    }

    void freeCryptoMachine()
    {
        delete this->getCryptoMachine();
        this->setCryptoMachine(nullptr);
    }

    bool allocateCryptoMachine()
    {
        switch (this->getCryptoOp())
        {
        case Decrypt:
            this->setCryptoMachine(DecryptionMachine::create());
            break;
        case Encrypt:
            this->setCryptoMachine(EncryptionMachine::create());
            break;
        default:
            return false;
        }

        return this->cryptoMachineSet();
    }

    bool initCryptoMachine(CryptoOp cryptoOp)
    {
        this->setCryptoOp(cryptoOp);

        this->freeCryptoMachine();
        bool ok = this->allocateCryptoMachine();

        this->cryptoMachineAssignKey();

        return ok;
    }

    void init()
    {
        this->setCryptoMachine(nullptr);
        this->setKey(nullptr);
    }

public:
    CryptoContext(CryptoType cryptoType, CryptoOp cryptoOp)
    {
        this->init();
        this->setup(cryptoType, cryptoOp);
    }

    CryptoContext() { this->init(); }

    ~CryptoContext() { this->cleanup(); }

    bool setup(CryptoType cryptoType, CryptoOp cryptoOp)
    {
        return this->initKey(cryptoType, cryptoOp) and
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

    bool setKey(ConstBytes key, Size keylen)
    {
        if (this->keySet())
        {
            return this->getKey()->setKeyData(key, keylen);
        }

        return false;
    }

    bool readKey(ConstPlaintext path, Plaintext passphrase)
    {
        if (this->keySet())
        {
            return this->getKey()->readKeyFile(path, passphrase);
        }

        return false;
    }

    bool readKey(ConstPlaintext path)
    {
        return this->readKey(path, nullptr);
    }

    bool setForEncryption() const
    {
        return this->cryptoMachineSet() and this->getCryptoOp() == Encrypt;
    }

    void setPlaintext(ConstBytes data, Size datalen)
    {
        if (this->setForEncryption())
        {
            this->getCryptoMachine()->setInput(data, datalen);
        }
    }

    bool setForDecryption() const
    {
        return this->cryptoMachineSet() and this->getCryptoOp() == Decrypt;
    }

    const EncrypterData *getPlaintext() const
    {
        if (this->setForDecryption())
        {
            return this->getCryptoMachine()->getOutput();
        }

        return nullptr;
    }

    void setCiphertext(ConstBytes data, Size datalen)
    {
        if (this->setForDecryption())
        {
            this->getCryptoMachine()->setInput(data, datalen);
        }
    }

    const EncrypterData *getCiphertext() const
    {
        if (this->setForEncryption())
        {
            return this->getCryptoMachine()->getOutput();
        }

        return nullptr;
    }

    void run()
    {
        if (this->cryptoMachineSet())
        {
            this->getCryptoMachine()->run();
        }
    }

    void cleanup()
    {
        this->freeCryptoMachine();
        this->freeKey();
    }
};

#endif