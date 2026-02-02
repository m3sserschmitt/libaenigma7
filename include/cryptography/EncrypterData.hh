#ifndef ENCRYPTER_DATA_HH
#define ENCRYPTER_DATA_HH

#include <cstring>

class EncrypterData
{
private:
    unsigned char *data;
    unsigned int dataSize;

public:
    EncrypterData(const unsigned char *data, unsigned int dataLen)
    {
        this->dataSize = dataLen;
        this->data = new unsigned char[dataLen + 1];
        if (data)
        {
            memcpy(this->data, data, dataLen);
        }
    }

    EncrypterData(const EncrypterData &) = delete;
    const EncrypterData &operator=(const EncrypterData &) = delete;

    virtual ~EncrypterData()
    {
        if (this->data)
        {
            memset(this->data, 0, dataSize);
        }

        delete[] this->data;
        this->data = nullptr;
    }

    [[nodiscard]] unsigned int getDataSize() const { return this->dataSize; }

    [[nodiscard]] const unsigned char *getData() const { return this->data; }

    [[nodiscard]] virtual bool isError() const { return false; }
};

#endif
