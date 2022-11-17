#ifndef ENCRYPTER_RESULT_HH
#define ENCRYPTER_RESULT_HH

#include "EncrypterData.hh"

class EncrypterResult : public EncrypterData
{
    bool ok;
public:
    EncrypterResult(const Byte *data, Size datalen) : EncrypterData(data, datalen) 
    {
        this->ok = true;
    }

    EncrypterResult(bool ok) : EncrypterData(nullptr, 0)
    {
        this->ok = ok;
    }

    bool isError() const
    {
        return not this->ok;
    }
};

#endif