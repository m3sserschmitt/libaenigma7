#ifndef ENCRYPTER_DATA_HH
#define ENCRYPTER_DATA_HH

#include "Types.hh"

#include <cstring>

class EncrypterData
{
    Bytes data;
    Size datalen;

    EncrypterData(const EncrypterData &);
    const EncrypterData &operator=(const EncrypterData &);

public:
    EncrypterData(const Byte *data, Size datalen)
    {
        this->datalen = datalen;
        this->data = new Byte[datalen + 1];
        memcpy(this->data, data, datalen);
    }

    virtual ~EncrypterData()
    {
        memset(this->data, 0, datalen);
        delete[] this->data;
        this->data = nullptr;
    }

    Size getDataSize() const
    {
        return this->datalen;
    }

    const Byte *getData() const
    {
        return this->data;
    }

    virtual bool isError() const { return false; }
};

#endif
