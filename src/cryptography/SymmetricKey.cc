#include "../../include/cryptography/SymmetricKey.hh"
#include "../../include/cryptography/CipherContext.hh"

#include <openssl/evp.h>

/*
void SymmetricKey::initDecryption(const EncrypterData *data)
{
    Size encrlen = data->getDataSize() - IV_SIZE - TAG_SIZE;
    const Byte *payload = data->getData();

    this->createBuffer(encrlen);
    this->createCipherContext();
    this->initIV(payload);
    this->initTagData(payload + data->getDataSize() - TAG_SIZE);
}

EncrypterResult *SymmetricKey::prepareEncryptedBuffer()
{
    Size bufferSize = this->getBufferSize();
    Size finalDataSize = bufferSize + IV_SIZE + TAG_SIZE;

    Bytes buffer = this->getBuffer();

    Bytes finalData = new Byte[finalDataSize + 1];

    memcpy(finalData, this->ivData, IV_SIZE);
    memcpy(finalData + IV_SIZE, buffer, bufferSize);
    memcpy(finalData + IV_SIZE + bufferSize, this->tagData, TAG_SIZE);

    EncrypterResult *result = new EncrypterResult(finalData, finalDataSize);
    memset(finalData, 0, finalDataSize);
    delete[] finalData;

    return result;
}
*/
const EncrypterResult *SymmetricKey::lock(const EncrypterData *data)
{
    CipherContext cipherContext(this->getKeyData());

    return cipherContext.encrypt(data);
}

const EncrypterResult *SymmetricKey::unlock(const EncrypterData *data)
{
    CipherContext cipherContext(this->getKeyData());

    return cipherContext.decrypt(data);
}
