#include "cryptography/CryptoContext.hh"
#include "cryptography/SymmetricEvpCipherContext.hh"
#include "cryptography/AsymmetricEvpCipherContext.hh"
#include "cryptography/EvpMdContext.hh"

bool CryptoContext::allocateKey()
{
    switch (this->getCryptoType())
    {
    case SymmetricCryptography:
        this->setKey(SymmetricKey::Factory::create());
        break;
    case AsymmetricCryptography:
        switch (this->getCryptoOp())
        {
        case Encrypt:
        case SignVerify:
            this->setKey(AsymmetricKey::Factory::createPublicKey());
            break;
        case Decrypt:
        case Sign:
            this->setKey(AsymmetricKey::Factory::createPrivateKey());
            break;
        default:
            return false;
        }
        break;
    default:
        return false;
    }

    return this->notNullKey();
}

bool CryptoContext::allocateCipher()
{
    if (not this->notNullKey())
    {
        return false;
    }

    switch (this->getCryptoType())
    {
    case SymmetricCryptography:
        this->setCipher(SymmetricEvpCipherContext::create(this->getKey()));
        break;
    case AsymmetricCryptography:
        switch (this->getCryptoOp())
        {
        case Encrypt:
        case Decrypt:
            this->setCipher(AsymmetricEvpCipherContext::create(this->getKey()));
            break;
        case Sign:
        case SignVerify:
            this->setCipher(EvpMdContext::create(this->getKey()));
            break;
        default:
            return false;
        }

        break;
    default:
        return false;
    }

    return this->notNullCipher();
}

bool CryptoContext::allocateCryptoMachine()
{
    if (not this->notNullCipher())
    {
        return false;
    }

    switch (this->getCryptoOp())
    {
    case Decrypt:
    case SignVerify:
        this->setCryptoMachine(DecryptionMachine::create(this->getCipher()));
        break;
    case Encrypt:
    case Sign:
        this->setCryptoMachine(EncryptionMachine::create(this->getCipher()));
        break;
    default:
        return false;
    }

    return this->notNullCryptoMachine();
}
