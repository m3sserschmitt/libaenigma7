#ifndef CRYPTO_CONTEXT_HH
#define CRYPTO_CONTEXT_HH

#include "EncryptionMachine.hh"
#include "DecryptionMachine.hh"
#include "SymmetricKey.hh"
#include "AsymmetricKey.hh"
#include "enums/CryptoOp.hh"
#include "enums/CryptoType.hh"
#include "contracts/ICryptoContext.hh"

class CryptoContext : public ICryptoContext
{
    CryptoType cryptoType;
    CryptoOp cryptoOp;

    Key *key;
    EvpContext *cipher;
    CryptoMachine *cryptoMachine;

    CryptoContext(const CryptoContext &);
    const CryptoContext &operator=(const CryptoContext &);

    void setKey(Key *key) { this->key = key; }

    Key *getKey() { return this->key; }

    void setCryptoMachine(CryptoMachine *cryptoMachine) { this->cryptoMachine = cryptoMachine; }

    CryptoMachine *getCryptoMachine() { return this->cryptoMachine; }

    const CryptoMachine *getCryptoMachine() const { return this->cryptoMachine; }

    EvpContext *getCipher() { return this->cipher; }

    void setCipher(EvpContext *cipher) { this->cipher = cipher; }

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

    CryptoContext(CryptoType cryptoType, CryptoOp cryptoOp)
    {
        this->init();
        this->setCryptoType(cryptoType);
        this->setCryptoOp(cryptoOp);
        this->setup();
    }

    CryptoContext() { this->init(); }

public:
    ~CryptoContext() { this->cleanup(); }

    CryptoOp getCryptoOp() const { return this->cryptoOp; }

    CryptoType getCryptoType() const { return this->cryptoType; }

    void setCryptoType(CryptoType cryptoType) { this->cryptoType = cryptoType; }

    void setCryptoOp(CryptoOp cryptoOp) { this->cryptoOp = cryptoOp; }

    bool setup()
    {
        return this->initKey() and
               this->initCipher() and
               this->initCryptoMachine();
    }

    bool setKey256(ConstBytes key)
    {
        return this->notNullKey() and this->getKey()->setKeyData(key, SYMMETRIC_KEY_SIZE);
    }

    bool setKeyData(ConstPlaintext key, char *passphrase = nullptr)
    {
        return this->notNullKey() and this->getKey()->setKeyData((ConstBytes)key, strlen(key), passphrase);
    }

    bool readKeyFile(ConstPlaintext path, Plaintext passphrase = nullptr)
    {
        return this->notNullKey() and this->getKey()->readKeyFile(path, passphrase);
    }

    bool isSetForEncryption() const
    {
        return this->notNullCryptoMachine() and this->getCryptoOp() == Encrypt;
    }

    bool isSetForSigning() const
    {
        return this->notNullCryptoMachine() and this->getCryptoOp() == Sign;
    }

    bool setPlaintext(ConstBytes data, Size datalen)
    {
        return (this->isSetForEncryption() or this->isSetForSigning()) and this->getCryptoMachine()->setInput(data, datalen);
    }

    bool isSetForDecryption() const
    {
        return this->notNullCryptoMachine() and this->getCryptoOp() == Decrypt;
    }

    bool isSetForVerifying() const
    {
        return this->notNullCryptoMachine() and this->getCryptoOp() == SignVerify;
    }

    const EncrypterData *getPlaintext() const
    {
        return this->isSetForDecryption() or this->isSetForVerifying() ? this->getCryptoMachine()->getOutput() : nullptr;
    }

    bool setCiphertext(ConstBytes data, Size datalen)
    {
        return (this->isSetForDecryption() or this->isSetForVerifying()) and this->getCryptoMachine()->setInput(data, datalen);
    }

    const EncrypterData *getCiphertext() const
    {
        return this->isSetForEncryption() or this->isSetForSigning() ? this->getCryptoMachine()->getOutput() : nullptr;
    }

    bool run() { return this->notNullCryptoMachine() and this->getCryptoMachine()->run(); }

    void cleanup()
    {
        this->freeCryptoMachine();
        this->freeKey();
    }

    static CryptoContext *createAesEncryptionContext()
    {
        return new CryptoContext(SymmetricCryptography, Encrypt);
    }

    static CryptoContext *CreateAesDecryptionContext()
    {
        return new CryptoContext(SymmetricCryptography, Decrypt);
    }

    static CryptoContext *createRsaEncryptionContext()
    {
        return new CryptoContext(AsymmetricCryptography, Encrypt);
    }

    static CryptoContext *createRsaDecryptionContext()
    {
        return new CryptoContext(AsymmetricCryptography, Decrypt);
    }

    static CryptoContext *createRsaSignatureContext()
    {
        return new CryptoContext(AsymmetricCryptography, Sign);
    }

    static CryptoContext *createRsaSignatureVerificationContext()
    {
        return new CryptoContext(AsymmetricCryptography, SignVerify);
    }

    static CryptoContext *CreateCryptoContext()
    {
        return new CryptoContext();
    }
};

#endif