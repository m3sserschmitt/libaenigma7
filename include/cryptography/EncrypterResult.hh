#ifndef ENCRYPTER_RESULT_HH
#define ENCRYPTER_RESULT_HH

#include "EncrypterData.hh"

class EncrypterResult : public EncrypterData
{
    bool ok;

    EncrypterResult(const EncrypterResult &);
    const EncrypterResult &operator=(const EncrypterResult &);
    
public:
    EncrypterResult(ConstBytes data, Size datalen) : EncrypterData(data, datalen) 
    {
        this->ok = true;
    }

    EncrypterResult(bool ok) : EncrypterData(nullptr, 0)
    {
        this->ok = ok;
    }

    bool isError() const override
    {
        return not this->ok;
    }
};

#endif