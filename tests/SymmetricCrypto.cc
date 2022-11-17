#include <iostream>

#include "../include/cryptography/EncryptionMachine.hh"
#include "../include/cryptography/DecryptionMachine.hh"
#include "../include/cryptography/SymmetricKey.hh"

using namespace std;

int main()
{
    const Byte *keyData = (const Byte *)"encryption key for testing 1234";

    Key *symmetricKey = new SymmetricKey;
    CryptoMachine *encryptionMachine = new EncryptionMachine;
    CryptoMachine *decryptionMachine = new DecryptionMachine;

    symmetricKey->setKeyData(keyData, 32);

    encryptionMachine->setData((const Byte *)"test", 4);
    encryptionMachine->setKey(symmetricKey);

    

    encryptionMachine->run();

    const EncrypterData *encrypterData = encryptionMachine->getResult();

    decryptionMachine->setData(encrypterData->getData(), encrypterData->getDataSize());
    decryptionMachine->setKey(symmetricKey);

    decryptionMachine->run();

    cout << "status:" << decryptionMachine->getResult()->isError() << "\ndecrypted data: "<< decryptionMachine->getResult()->getData() << "\n";

    return EXIT_SUCCESS;
}