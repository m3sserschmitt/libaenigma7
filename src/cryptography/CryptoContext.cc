#include "../../include/cryptography/CryptoContext.hh"

bool CryptoContext::allocateKey()
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
        this->setCipher(SymmetricCipher::create(this->getKey()));
        break;
    case AsymmetricCryptography:
        this->setCipher(AsymmetricCipher::create(this->getKey()));
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
        this->setCryptoMachine(DecryptionMachine::create(this->getCipher()));
        break;
    case Encrypt:
        this->setCryptoMachine(EncryptionMachine::create(this->getCipher()));
        break;
    default:
        return false;
    }

    return this->notNullCryptoMachine();
}
