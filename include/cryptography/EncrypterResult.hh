#ifndef ENCRYPTER_RESULT_HH
#define ENCRYPTER_RESULT_HH

#include "EncrypterData.hh"

class EncrypterResult : public EncrypterData
{
private:
    bool ok;

public:
    EncrypterResult(const unsigned char *data, unsigned int dataLen) : EncrypterData(data, dataLen)
    {
        this->ok = true;
    }

    explicit EncrypterResult(bool ok) : EncrypterData(nullptr, 0)
    {
        this->ok = ok;
    }

    EncrypterResult(const EncrypterResult &) = delete;
    const EncrypterResult &operator=(const EncrypterResult &) = delete;

    [[nodiscard]] bool isError() const override { return not this->ok; }
};

#endif
