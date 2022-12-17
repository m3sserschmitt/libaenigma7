#include <iostream>

#include "../include/cryptography/CryptoContext.hh"

using namespace std;

bool testSymmetricCrypto()
{
    const Byte *key = RandomDataGenerator::generate(SYMMETRIC_KEY_SIZE)->getData();
    const Byte *data = RandomDataGenerator::generate(128)->getData();

    CryptoContext *cryptoContext = new CryptoContext(SymmetricCryptography, Encrypt);

    cryptoContext->setKey(key, SYMMETRIC_KEY_SIZE);
    cryptoContext->setPlaintext(data, 128);
    cryptoContext->run();

    const EncrypterData *encr = cryptoContext->getCiphertext();
    
    if (encr->isError())
    {
        return false;
    }

    Size datalen = encr->getDataSize();
    Bytes encrdata = new Byte[datalen + 1];
    memcpy(encrdata, encr->getData(), datalen);

    cryptoContext->init(SymmetricCryptography, Decrypt);
    cryptoContext->setKey(key, SYMMETRIC_KEY_SIZE);
    cryptoContext->setCiphertext(encrdata, datalen);

    cryptoContext->run();

    const EncrypterData *ciphertext = cryptoContext->getPlaintext();

    if (ciphertext->isError())
    {
        return false;
    }

    return memcmp(data, ciphertext->getData(), 128) == 0;
}

int main()
{
    bool success = testSymmetricCrypto();

    if (success)
    {
        cout << "Success!\n";
    }
    else
    {
        cout << "Failure!\n";
    }

    return EXIT_SUCCESS;
}