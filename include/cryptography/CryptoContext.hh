#ifndef CRYPTO_CONTEXT_HH
#define CRYPTO_CONTEXT_HH

#include "EncryptionMachine.hh"
#include "DecryptionMachine.hh"
#include "SymmetricKey.hh"
#include "AsymmetricKey.hh"
#include "AsymmetricCipher.hh"
#include "SymmetricCipher.hh"

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
    Cipher *cipher;
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

    Cipher *getCipher() { return this->cipher; }

    void setCipher(Cipher *cipher) { this->cipher = cipher; }

    bool notNullCryptoMachine() const { return this->cryptoMachine != nullptr; }

    bool notNullKey() const { return this->key != nullptr; }

    bool notNullCipher() const { return this->cipher != nullptr; }

    void freeKey()
    {
        delete this->getKey();
        this->setKey(nullptr);
    }

    bool allocateKey();

    bool initKey()
    {
        this->freeKey();
        return this->allocateKey();
    }

    void freeCipher()
    {
        delete this->getCipher();
        this->setCipher(nullptr);
    }

    bool allocateCipher();

    bool initCipher()
    {
        this->freeCipher();
        return this->allocateCipher();
    }

    void freeCryptoMachine()
    {
        delete this->getCryptoMachine();
        this->setCryptoMachine(nullptr);
    }

    bool allocateCryptoMachine();

    bool initCryptoMachine()
    {
        this->freeCryptoMachine();
        return this->allocateCryptoMachine();
    }

    void init()
    {
        this->setCryptoMachine(nullptr);
        this->setKey(nullptr);
        this->setCipher(nullptr);
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
        this->setCryptoType(cryptoType);
        this->setCryptoOp(cryptoOp);

        return this->initKey() and
               this->initCipher() and
               this->initCryptoMachine();
    }

    CryptoOp getCryptoOp() const { return this->cryptoOp; }

    CryptoType getCryptoType() const { return this->cryptoType; }

    bool setKeyData(ConstBytes key, Size keylen)
    {
        return this->notNullKey() and this->getKey()->setKeyData(key, keylen);
    }

    bool readKeyData(ConstPlaintext path, Plaintext passphrase)
    {
        return this->notNullKey() and this->getKey()->readKeyFile(path, passphrase);
    }

    bool readKeyData(ConstPlaintext path) { return this->readKeyData(path, nullptr); }

    bool isSetForEncryption() const
    {
        return this->notNullCryptoMachine() and this->getCryptoOp() == Encrypt;
    }

    bool setPlaintext(ConstBytes data, Size datalen)
    {
        return this->isSetForEncryption() and this->getCryptoMachine()->setInput(data, datalen);
    }

    bool setForDecryption() const
    {
        return this->notNullCryptoMachine() and this->getCryptoOp() == Decrypt;
    }

    const EncrypterData *getPlaintext() const
    {
        return this->setForDecryption() ? this->getCryptoMachine()->getOutput() : nullptr;
    }

    bool setCiphertext(ConstBytes data, Size datalen)
    {
        return this->setForDecryption() and this->getCryptoMachine()->setInput(data, datalen);
    }

    const EncrypterData *getCiphertext() const
    {
        return this->isSetForEncryption() ? this->getCryptoMachine()->getOutput() : nullptr;
    }

    bool run() { return this->notNullCryptoMachine() and this->getCryptoMachine()->run(); }

    void cleanup()
    {
        this->freeCryptoMachine();
        this->freeKey();
    }
};

#endif