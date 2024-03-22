#include "cryptography/CryptoContext.hh"
#include "cryptography/SymmetricEvpCipherContext.hh"
#include "cryptography/AsymmetricEvpCipherContext.hh"
#include "cryptography/EvpMdContext.hh"

bool CryptoContext::allocateKey()
{
    switch (this->getCryptoType())
    {
    case SymmetricCryptography:
        this->key = SymmetricKey::Factory::create();
        break;
    case AsymmetricCryptography:
        switch (this->getCryptoOp())
        {
        case Encrypt:
        case SignVerify:
            this->key = AsymmetricKey::Factory::createPublicKey();
            break;
        case Decrypt:
        case Sign:
            this->key = AsymmetricKey::Factory::createPrivateKey();
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
        this->cipher = SymmetricEvpCipherContext::Factory::create(this->key);
        break;
    case AsymmetricCryptography:
        switch (this->getCryptoOp())
        {
        case Encrypt:
        case Decrypt:
            this->cipher = AsymmetricEvpCipherContext::Factory::create(this->key);
            break;
        case Sign:
        case SignVerify:
            this->cipher = EvpMdContext::Factory::create(this->key);
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
        this->cryptoMachine = DecryptionMachine::create(this->cipher);
        break;
    case Encrypt:
    case Sign:
        this->cryptoMachine = EncryptionMachine::create(this->cipher);
        break;
    default:
        return false;
    }

    return this->notNullCryptoMachine();
}
