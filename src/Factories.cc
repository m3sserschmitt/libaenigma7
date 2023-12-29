#include "cryptography/CryptoContextBuilder.hh"

extern "C"
{
    CryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useAes()
                                     ->useEncryption()
                                     ->noPlaintext()
                                     ->setKey256(key)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useAes()
                                     ->useDecryption()
                                     ->noCiphertext()
                                     ->setKey256(key)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateAsymmetricDecryptionContext(const char *key, const char *passphrase)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useDecryption()
                                     ->noCiphertext()
                                     ->setKey(key, passphrase)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateAsymmetricEncryptionContext(const char *key)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useEncryption()
                                     ->noPlaintext()
                                     ->setKey(key)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useEncryption()
                                     ->noPlaintext()
                                     ->readKeyData(path)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *file, const char *passphrase)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useDecryption()
                                     ->noCiphertext()
                                     ->readKeyData(file, passphrase)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateSignatureContext(const char *key, const char *passphrase)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useSignature()
                                     ->noPlaintext()
                                     ->setKey(key, passphrase)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateVerificationContext(const char *key)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useSignatureVerification()
                                     ->noCiphertext()
                                     ->setKey(key)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateSignatureContextFromFile(const char *path, const char *passphrase)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useSignature()
                                     ->noPlaintext()
                                     ->readKeyData(path, passphrase)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }

    CryptoContext *CreateVerificationContextFromFile(const char *path)
    {
        ICryptoContextBuilderType *builder = CryptoContextBuilder::Create();
        try
        {
            CryptoContext *ctx = builder->useRsa()
                                     ->useSignatureVerification()
                                     ->noCiphertext()
                                     ->readKeyData(path)
                                     ->build();
            delete builder;
            return ctx;
        }
        catch (std::exception)
        {
            delete builder;
            return nullptr;
        }
    }
}
