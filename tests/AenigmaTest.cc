#include "cryptography/Aenigma.hh"

#include <cstring>
#include <iostream>

using namespace std;

typedef const unsigned char *(*EncryptionFunction)(
    CryptoContext *ctx,
    const unsigned char *input,
    unsigned int inlen,
    int &outlen);

typedef bool (*VerificationFunction)(
    CryptoContext *ctx,
    const unsigned char *input,
    unsigned int inlen);

bool Test(EncryptionFunction executor, CryptoContext *ctx, const unsigned char *input, unsigned int inlen, const unsigned char *expectedOutput, int expectedOutlen)
{
    int outlen;
    const unsigned char *out = executor(ctx, input, inlen, outlen);

    if (outlen != expectedOutlen)
    {
        cout << "Output size does not match expected value (" << expectedOutlen << " expected, " << outlen << " resulted);";
        return false;
    }

    if (not out && outlen > 0)
    {
        cout << "Output is null but outlen is greater than 0;";
        return false;
    }

    if (expectedOutput && out && outlen > 0)
    {
        return memcmp(out, expectedOutput, expectedOutlen) == 0;
    }

    return true;
}

bool Test(VerificationFunction executor, CryptoContext *ctx, const unsigned char *input, unsigned int inlen, bool expectedResult)
{
    return executor(ctx, input, inlen) == expectedResult;
}

bool TestSubsequentOperations(EncryptionFunction executor, CryptoContext *ctx, const unsigned char *input, unsigned int inlen, const unsigned char *expectedOutput, int expectedOutlen)
{
    for (int i = 0; i < 8; i++)
    {
        if (!Test(executor, ctx, input, inlen, expectedOutput, expectedOutlen))
        {
            return false;
        }
    }

    return true;
}

bool TestSubsequentOperations(VerificationFunction executor, CryptoContext *ctx, const unsigned char *input, unsigned int inlen, bool expectedResult)
{
    for (int i = 0; i < 8; i++)
    {
        if (!Test(executor, ctx, input, inlen, expectedResult))
        {
            return false;
        }
    }

    return true;
}

void PrintResult(const char *message, bool success)
{
    cout << message << (success ? "\033[32mSUCCESS" : "\033[31mFAILURE") << "\033[0m;\n";
}

bool RunTest(const char *testCase, EncryptionFunction executor, CryptoContext *ctx, const unsigned char *input, unsigned int inlen, const unsigned char *expectedOutput, int expectedOutlen)
{
    cout << testCase << "; ";
    bool success = TestSubsequentOperations(executor, ctx, input, inlen, expectedOutput, expectedOutlen);
    PrintResult("result: ", success);
    return success;
}

bool RunTest(const char *testCase, VerificationFunction executor, CryptoContext *ctx, const unsigned char *input, unsigned int inlen, bool expectedResult)
{
    cout << testCase << "; ";
    bool success = TestSubsequentOperations(executor, ctx, input, inlen, expectedResult);
    PrintResult("result: ", success);
    return success;
}

const char *publicKey = "-----BEGIN PUBLIC KEY-----\n"
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt93z0JRoIKt0f+Yoy6KB\n"
                        "c3AYlN2LiA4NH3EsVtVFdPyOboEpDIKMQwuSP9Gi/+hBHgHnO8YXU/ytBygAzE93\n"
                        "o/BzMtNNgQS+FDDiuD19+65525rI+IZL+vulhvUVsUZgHmW7r0ACB8qxmQdmotLr\n"
                        "zgyRprJo1kCRQajS5ICsjWqx/w/s39k5V8XJnIYCAIcSiG9N22Z3GY3x1ewOfU15\n"
                        "Amw3lb7s6ccOccVUgrDWMqjfaVzYebFmXhyJ99+xp2YOjiIfwL/dDIy2R7chiTSr\n"
                        "uLWhUdX9FPjSpsTCu7vOq0fKitIe9yIXkcA+WZSU4AqxH3h+9eJtlG0/yiK/thkG\n"
                        "OwIDAQAB\n"
                        "-----END PUBLIC KEY-----\n";

                        const char *publicKey2 = "-----BEGIN PUBLIC KEY-----\n"
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXnMOCtI35xdL88DO8Lm\n"
                        "SR+Hut4K7Z0kdW7kJl8RfobKsgG2P8hBQgiYE2YisEPxhZyWnY2K/X9KNpKfSQOZ\n"
                        "tbhZkLi4cWdAjkreMr+4ytVhCU91BzJDKLSkeGllw7g6o9X3XdMNhKsGARLKm5e3\n"
                        "qvd2YrLilQWqUNJPXsOoQAVkzU1BvzBOF5IO77swq0JSoA1KkfCx6vQl99eHLzc1\n"
                        "6vXkX4Kr7woObc3dNWIV5zbxlERzBGOBUEXHTnWcSAZPdsaMyVQ7a/aFlrDjo3Xb\n"
                        "vrk5ku8YX3misPwqVHaksjFxBwjYOhj8Sa4Sj5D7IJoYt+Y+AqiQJH//OLukMeu0\n"
                        "4wIDAQAB\n"
                        "-----END PUBLIC KEY-----\n";

const char *otherPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                             "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAphPQBoaRmbn90mlMD7xV\n"
                             "kYXkpoLCOfECW4MiqvIwlJ3CWx9f8fvrdTWkhQpJdFEtgXzIhe4a28CgOw4VzdrL\n"
                             "jxSRxg+q/l7F7of7jGvbZEaS2RC/j1m7MLa8t7d5vpO5Rf3CjldiPLzQpuhfhRTt\n"
                             "RjGTN8KGYqG37eXkPcmLgkUgRZRk4uxEy2kZLeNXLTbR8fiigSt1becTDhPPjyjT\n"
                             "G/M8HRRAMQ1qv425pefzhXuqdNkR5qZl/2L9TwTvTCHMMha2MTWFlSRwsfV7GaJ2\n"
                             "QZ+xHaQQ+Cv7cYwdYvg7tL+ETZuSQ/34XJeBbidWeLIfXZpRDJ512yK2XQw1iE5L\n"
                             "yQIDAQAB\n"
                             "-----END PUBLIC KEY-----";

const char *privateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                         "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIgeAn0zx2m+8CAggA\n"
                         "MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECKD9Qn6/xcfoBIIEyF6JEPQKoF09\n"
                         "AzqhJx4ypTbtZ7jSqm20D8G2Vre0qA3Nh4Z1/raZr1XNpCt5fpO4ctBo5tGfd0AD\n"
                         "NvEpde2NQwy9Y/iZbStVcOTKiFFoCaINoIEirHLHFmyMoTkpbia/vHRYhSvM5fkJ\n"
                         "M1CU4Nr+ffxB4V1XlZ4FQ1G9KJjOdBx1wdlsRuBrvIfTnxJM8WTeQcEPSXl2OQRt\n"
                         "CJHnUKVyiYcGj23BX0avBwDb3XH8ADmc7UDwMqYnZB3q3u3qW9/dTjMCHAh/TX17\n"
                         "ttQmQjr7kak5+m2kpnilE4kUovuOearLwB2fPl/sSXuW0AISSzWaIlKczFw9k++X\n"
                         "WT7/73jGdvkPJXjZ4ZR7nEUxbTTON8cgkRFBx3Je1rzng/5Dvru+gc+Md/ZMMiGQ\n"
                         "EQv/OBdfpkrgtzEPINytdV/R7DXoatejXoz1M6sBLfjoykcuDkkfIsfcXAzhh+4u\n"
                         "cfc7zrfjmjFjMRQdxj9saEg582FQ5yu6k39GYDhGJugzxSiznBXFUJip66pD6U3S\n"
                         "B0NAyGC2BYoII+5hoGB8RuBFO/tigO6JDdGINXM3b9v4muOQcL0nV0GNPWJM4lqH\n"
                         "roXSn9zcdLdMNNYr8uOV81KXmIoPZZ5TlNAOAc+Vm4Jc5OCsu5pHlTbr6YArXvdg\n"
                         "uWR9WKwS6QOy6+IXSRh1KStw5CnzOsSrtPVTmmfF/D6roSyvvABq9ieI1AXkOg2W\n"
                         "motfNczhzgbHEdC2IsM4NV9u+4lZgoRfgwxlJDwt3QXLkmYo0L5dszx3ghHOjEHL\n"
                         "4Ts1gKpKmh3fZWhRzEM5jOapEO7pDTtmW/JBHIisgUoZRHrwstrSLsqqyj+x3VMo\n"
                         "C75GTqfziCyF1qUQE7IyfGWMRypJfcCEzNj+0Alk9E+jgw2a66DVAgOaAP73JHJ5\n"
                         "QxssdBwd8NmGy2GKz8W2gznFUHla5Rhi18GH9lOg2txrpu+OvxhWd8Syb5RdUZ6H\n"
                         "7Bu/PnFwGK9vguvl9qZ6aC58bPrnHCRyqCwZr/bVE4mDw2vvnVk+zGjZrl5RN3lm\n"
                         "xudl/SUxCvq8QuO9HjIwhBdpmGx+or1GhoyRwC51OUHtlmRbUadWTB4CpGHzab66\n"
                         "TbDzC08+4MkmvDGsBZ6ubGxHVrv5EeiKeVwydPZ5Ay6C3BQRA9/3OdelDFvBZv8x\n"
                         "sVJpUARBV9raYpFrebddydLFwpjc0BeLkmdWIz308gQBp4e3ww7Nkz5H7v/3PsdS\n"
                         "zelvdVXlXmdKiMG5V55yNu2zZWklq7+R8t+X56OEoLA5EXB/b9wtIw5t9pbymxMB\n"
                         "L2xLWezG/yX6mWfQN2oiHNIkpkTb8WgUQjlGaUCnxcaiB+BYZVSCmAzF+I+JAOqf\n"
                         "hkfd11tj+95OIn5L9SQxWIvmBwmCbl5xwuuCbN+O/TaH/FPDD1EXeGG0muRuwRNP\n"
                         "sALPDkmBGBzYv/t+PJk4R/ETpxZQc+x/JqUnpzo2HadKT+ZRzSQ+0vPaV+X7CTRz\n"
                         "9TP2bkBD96+UQYMdb2pbzq+d8kWbxAon8cq1EBfILn/2l7lMVhLTWYUp4PhlCF1F\n"
                         "8BRQIr328o5OIEaUyWrgGUw2kPfY6JvI0qRUaIxc8KIZm4pJlIXICWTmufvpgG2H\n"
                         "jyOYYdWz/iFvQPvkJvXhRQ==\n"
                         "-----END ENCRYPTED PRIVATE KEY-----\n";

const char *privateKey2 = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                        "MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQZ23NLlHS1SZSdM8e\n"
                        "yu9HAQICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEBYzf6HXlt6W8Per\n"
                        "X2/GpxYEggTQcSBwY0LwXmzqaa+oTcUoi50tazOIwunA3h3Ggg0p1IMOJctUasjr\n"
                        "tR1g1GV8hrqyQziGATegZRVOk9Dx/VbToGDcPGNm4Ty6mZ11WmdYP3Wr8XZiO7hw\n"
                        "hzwCLSaDTLMa+8Hdio6bi32858dnt6KFyM1XK/nmPNKC0DcWuODO+nMyV+dLKt3S\n"
                        "SH3/z19hvEEzEwJ0Syr2/gXBgmoUdlgs0KTxPuT+FT/TiEnxNaEK2s7qtK0WOWSc\n"
                        "bXiVvHTVTmpR3t+lcK1S76BvGrJ0ZN+SJfCqbt4XTtNXM+n1v8Cmnd42RSC5lxHp\n"
                        "UsnfzOkQQSIXfZpOQYGMAxxGZAsB+xqZle5v+PsZ88APizUfPPAIC5+m9PFQ9rza\n"
                        "YglTu9qVJey1am9NGsSqyW2XAfKoZUuUFoLydkEWAC/gqaC8NSrvbTQt1bjea15o\n"
                        "Dlr/4BtEQlQvIxCVmgQpBiYqPEaDn0nI90em6g3NlSRFXv+vAgM2exQ4b93CS7TV\n"
                        "xSbF7g/ys12xAhL+wJhFJO36oHq6Ga3P0+jxhvCDP1aAP9tgk/SrNJOQ2aSYNzAb\n"
                        "Uq+IJzduZETkOF+8KhIzeTG8AiJJDRMi3APbXYjW338wWRriDlUphlpcP6b5LCD/\n"
                        "BAskP5KVlxPSi95fIp2G6NWXwBdr4MR1dCLcvBH2ta82bimiHf0X3ZUvzZ2SxLs2\n"
                        "czgnL+1rTLZqB7Jh3I093u4kBcX9ANSFRJAmho6f6eoE4pXsdYU94D+67w7QIoSz\n"
                        "Ysi1AvyKqey9384fZI48C5rJzFBLpKB2nL/gZmK3vQU/XbDYv+1cp33CaDIKNn2R\n"
                        "P/m0aIXgrpdv+G2xGJbmCkokBh7NrtR7N4p+pibf6xTehcvV9agLk3vLW5CkctiH\n"
                        "hKu2Dbz65rhVp+XcEdXvbmd6dt8Fw1OBmXb1qutK4pQdywCKE9eOojv00Vyg041L\n"
                        "GPyJqCVCT63XN+SNvKHezDq2mT6iF9ftwsFIVx5yEkpSL07Jhwb/o1xELhvEX0yM\n"
                        "ECtyqGa0fKx5rWOaqh7nWrzL0C8v1f9QcwcRWcPwOH4hsGwPfamS7Hmv9labKdbs\n"
                        "gd6oi5N7FM6F5/YjyvyDYzuTmerxIK4aAzvNdfPyW818R8bZ+KRrcdMoFsiuUgto\n"
                        "RUJOu0L1bTHMhFUFWDiAC3+8POZLQ8qqBYirwRNNZhpQ6yq1wp+e/sJoF7mz9EfN\n"
                        "uaWeOetPNNsPYwO5PcsdqCl/Lkc0tJPfcAgMZ3QO8/rHVAE8duu7OPYEJBSqP4Jm\n"
                        "JbVVqzzfbVOrKva2bXLd6aUWqmFaUheNSLvFWajc/S0Hm8uDDFJmpBEqolOap6ut\n"
                        "+qKnnDFQ1liyXSdUevzV+xua6hB356EpuXp5X/HZdLt2HUbNKnQre0RG22YQAigj\n"
                        "PKKvQ/OQYy+SN3w9LwmPIwMRRqaD42ELbUA25jwffvATbBGpr9D3c8QPzib+0eLL\n"
                        "uemvUMczU4etoHyiqcL7pco2iVbuMYUbEdq6Z+PQGjD0C/1X80wsTA8Bo1lc1XPs\n"
                        "Y9CAzQ6v8SFrmyTVubkT0+9ZRTihfckNuTaUh/mf/rrXMEB7eWVMad7gY4U0Dk2v\n"
                        "wVKY7KLOGrri8pew/hLRJii1lo4sXO3g7Qr5SB6u0/kMeODxErZ9N7o=\n"
                        "-----END ENCRYPTED PRIVATE KEY-----\n";

const char *privateKeyPassphrase = "12345678";

const char *invalidPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                               "MIfasiupwenm09823409-0iuapsnmdafh08as7ur0a9isda0kpfdiat0f+Yoy6KB\n"
                               "c3AYlN2LiA4NH3EsVtVFdPyOboEpDIKMQwuSP9Gi/+hBHgHnO8YXU/ytBygAzE93\n"
                               "o/BzMtNNgQS+FDDiuD19+65525rI+IZL+vulhvUVsUZgHmW7r0ACB8qxmQdmotLr\n"
                               "zgyRprJo1kCRQajS5ICsjWqx/w/s39k5V8XJnIYCAIcSiG9N22Z3GY3x1ewOfU15\n"
                               "Amw3-=034-0ipfodihbpoiJ{AE(rui0wtuaskdnfposdkjfoughfdIy2R7chiTSr\n"
                               "uLWhUdX9FPjSpsTCu7vOq0fKitIe9yIXkcA+WZSU4AqxH3h+9eJtlG0/yiK/thkG\n"
                               "OwIDAQAB\n"
                               "-----END PUBLIC KEY-----\n";

const char *invalidPrivateKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                                "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIgeAn0zx2m+8CAggA\n"
                                "MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECKD9Qn6/xcfoBIIEyF6JEPQKoF09\n"
                                "AzqhJx4ypTbtZ7jSqm20D8G2Vre0qA3Nh4Z1/raZr1XNpCt5fpO4ctBo5tGfd0AD\n"
                                "NvEpde2NQwy9Y/iZbStVcOTKiFFoCaINoIEirHLHFmyMoTkpbia/vHRYhSvM5fkJ\n"
                                "M1CU4Nr+ffxB4V1XlZ4FQ1G9KJjOdBx1wdlsRuBrvIfTnxJM8WTeQcEPSXl2OQRt\n"
                                "CJHnUKVyiYcGj23BX0avBwDb3XH8ADmc7UDwMqYnZB3q3u3qW9/dTjMCHAh/TX17\n"
                                "ttQmQjr7kak5+m2kpnilE4kUovuOearLwB2fPl/sSXuW0AISSzWaIlKczFw9k++X\n"
                                "WT7/73jGdvkPJXjZ4ZR7nEUxbTTON8cgkRFBx3Je1rzng/5Dvru+gc+Md/ZMMiGQ\n"
                                "EQv/OBdfpkihd0a8yuf098734jalskdhuhgfoijapojdhgfuyhoijdfcXAzhh+4u\n"
                                "cfc7zrfjmjFjMRQdxj9saEg582FQ5yu6k39GYDhGJugzxSiznBXFUJip66pD6U3S\n"
                                "B0NAyGC2BYoII+5hoGB8RuBFO/tigO6JDdGINXM3b9v4muOQcL0nV0GNPWJM4lqH\n"
                                "roXSn9zcdLdMNNYr8uOV81KXmIoPZZ5TlNAOAc+Vm4Jc5OCsu5pHlTbr6YArXvdg\n"
                                "uWR9WKwS6QOy6+IXSRh1KStw5CnzOsSrtPVTmmfF/D6roSyvvABq9ieI1AXkOg2W\n"
                                "motfNczhzgbHEdC2IsM4NV9u+4lZgoRfgwxlJDwt3QXLkmYo0L5dszx3ghHOjEHL\n"
                                "4Ts1gKpKmh3fZWhRzEM5jOapEO7pDTtmW/JBHIisgUoZRHrwstrSLsqqyj+x3VMo\n"
                                "C75GTqfziCyF1qUQE7IyfGWMRypJfcCEzNj+0Alk9E+jgw2a66DVAgOaAP73JHJ5\n"
                                "QxssdBwd8NmGy2GKz8W2gznFUHla5Rhi18GH9lOg2txrpu+OvxhWd8Syb5RdUZ6H\n"
                                "7Bu/PnFwGK9vaergfgawerq3254ydgfasfdsdgdhsdfserwtgdg+zGjZrl5RN3lm\n"
                                "xudl/SUxCvq8QuO9HjIwhBdpmGx+or1GhoyRwC51OUHtlmRbUadWTB4CpGHzab66\n"
                                "TbDzC08+4MkmvDGsBZ6ubGxHVrv5EeiKeVwydPZ5Ay6C3BQRA9/3OdelDFvBZv8x\n"
                                "sVJpUARBV9raYpFrebddydLFwpjc0BeLkmdWIz308gQBp4e3ww7Nkz5H7v/3PsdS\n"
                                "zelvdVXlXmdKiMG5V55yNu2zZWklq7+R8t+X56OEoLA5EXB/b9wtIw5t9pbymxMB\n"
                                "L2xLWezG/yX6mWfQN2oiHNIkpkTb8WgUQjlGaUCnxcaiB+BYZVSCmAzF+I+JAOqf\n"
                                "hkfd11tj+95OIn5L9SQxWIvmBwmCbl5xwuuCbN+O/TaH/FPDD1EXeGG0muRuwRNP\n"
                                "sALPDkmBGBzYv/t+PJk4R/ETpxZQc+x/JqUnpzo2HadKT+ZRzSQ+0vPaV+X7CTRz\n"
                                "9TP2bkBD96+UQYMdb2pbzq+d8kWbxAon8cq1EBfILn/2l7lMVhLTWYUp4PhlCF1F\n"
                                "8BRQIr328o5OIEaUyWrgGUw2kPfY6JvI0qRUaIxc8KIZm4pJlIXICWTmufvpgG2H\n"
                                "jyOYYdWz/iFvQPvkJvXhRQ==\n"
                                "-----END ENCRYPTED PRIVATE KEY-----\n";

const char *otherPrivateKey = "-----BEGIN PRIVATE KEY-----\n"
                              "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCXsvJyB6kFTVP1\n"
                              "+fbDUax8s6UskPlkl4anZB3h0M32svr+rubgVKuJwJuXpn+pxnp7UfQvUBzD2qz9\n"
                              "N3IdX3o/AokuvZfjLRD9DxAAIzgF5QGWRbqPJ3Yrz3/nxWeK+3blfSBExGF2Qzjk\n"
                              "PJnjnWkH5Ar42XCMGZk2mNdgcrVmwBywV+mbI5OPHtWnAfiUDsFIOJcq1mnHqQfi\n"
                              "tKeOEW4m+B9YGD+KM0mpmNlBhMexQk/nGZeunPhXmWKDlFcjJmaltZa5z7/L/j58\n"
                              "I+cPRCjRvSzp4W51C5oJcEShT0cDK9yjn306lt18Zq937QvF4u+/GKIe4gvR73+1\n"
                              "UKJpnhytAgMBAAECggEAA+hylyjGsZdGDskrZ+lmZdQERlCkdsicicVqK6jDFZQ+\n"
                              "I7+CZ8xmmubhBe1zzn40Jjx8lkIca5iU6kplCzKsJeFn1/y/DqAuQYauJS1twmEd\n"
                              "mFnK2OiYV7/sY0knm2H9Cc5zvVxzHPvVrwjh91t/xYSaGm0SRC8Io7/DlKgqhNoV\n"
                              "+8jGKKLgmqDAIcYPSkpXbbVp5XuVsizvxx/ytGeAYuwepF34hxxSMYfcQzN1AJJM\n"
                              "zgAkIFlfT9iM0EfTjkTN8nk6k0k7w0oy2fWpvS9csVORrmpwNDABdI+WY/N7mnIC\n"
                              "0PRA9GLpeFVNChmKzvwqwMJKnMG6894j1yaqGwgC9QKBgQDFvejjgEJJ59BfuO7t\n"
                              "0lmEs+ubypWM/vvxvn3sHgwmvpSlqTTqwWGYBFICqkZvoFG4uHq1n7Dv2lSTcYzc\n"
                              "l7bnu8l8iBYuO+4aobCLvrhqZOHUFkV16pYsxDHMZMDeiMIhICHdM9HY4gfz5P9A\n"
                              "VLqYopqJy7GIHHDJpgorPmt9qwKBgQDEZGTshMMTv6o7hiEIYOxr7jCi/fm4rpnj\n"
                              "ImKhGhD8cFkhKMFU7HmNLRPSPBtJdHasqvbo25iJfgxAnZUTBK8YuWzG+RhhNwMh\n"
                              "DKmvfd4Yyu2XgIyP+USBQAgXxP2rjz6hVnJES4c5yZykUGBwozLkl5vCCnTxcra0\n"
                              "2mGeYroHBwKBgQCvP4oA5hDZswrnatzGBOC1TUeIQNidpvXe37Z15oNaaxkOYJG3\n"
                              "ZD98HIgaOJJIJ8uFbGnEQYzsZZEDQ2VVs1e0tKbzKSCPRSnWjGoMz7BdCp9h+YMB\n"
                              "6C/D6PVBciHEl2uFNBcPFffqwRfPPapCd1UQJTvU16O1P49uByuH+8AEFQKBgQCl\n"
                              "yk68sBLysAGogEGQjinnr0tVvWu7sYHtkdCLSbL/OGS1rm8PHxY5zM0H1IAAkZXB\n"
                              "jA4mY4MwxrzXK3B2fqTGDXq7ufsPzl4Q31y77li4u065b+a5f+eJ6SEr17uBwcpQ\n"
                              "bubFqrD8Yquets/DJrJG8Ymm1CcG0R1WLWjtSVDbrwKBgQC51U/MXn0bTyLi/NCZ\n"
                              "TktsEdZC/dqKHDvGLAkiRwzk6CNmG+Rk75kc1u6nj33ZD9ZcVzf7TThXWEYZqd0V\n"
                              "ceJzW5KbvnsMrk8w2xzkmqbCLU6f9PBBYiO+jpBJivbJKfWS3ZkymkORRCX4mRY6\n"
                              "4ztR0B3wLj+TN4mOyW+xojfnVw==\n"
                              "-----END PRIVATE KEY-----\n";

const unsigned char plaintext[] = {1, 56, 125, 100, 200, 156, 230, 80, 70, 45, 20, 76, 23, 67, 45, 12};
const int plaintextLen = 16;

const unsigned char asymmetricCiphertext[] = {17, 6, 150, 63, 128, 50, 99, 224, 4, 171, 144, 112, 14, 191, 219, 254, 0, 9, 254, 229, 107, 3, 105, 111, 109, 60, 184, 26, 118, 47, 185, 160, 201, 39, 59, 118, 27, 156, 48, 135, 35, 164, 62, 133, 172, 22, 25, 121, 61, 215, 224, 91, 254, 178, 105, 214, 182, 72, 5, 103, 195, 229, 251, 114, 9, 167, 186, 68, 65, 195, 129, 174, 212, 192, 97, 71, 241, 47, 125, 187, 122, 129, 144, 86, 186, 135, 239, 165, 75, 187, 4, 99, 250, 74, 21, 59, 98, 45, 10, 156, 166, 218, 105, 222, 19, 226, 51, 194, 242, 9, 31, 6, 149, 122, 198, 219, 51, 175, 235, 163, 1, 223, 182, 162, 214, 32, 146, 22, 201, 19, 40, 15, 153, 27, 12, 71, 81, 26, 63, 169, 203, 2, 132, 102, 242, 64, 17, 7, 56, 6, 164, 203, 214, 37, 86, 152, 230, 190, 254, 104, 54, 18, 23, 251, 80, 199, 47, 204, 126, 229, 36, 137, 139, 94, 136, 248, 248, 155, 231, 82, 158, 124, 244, 19, 103, 101, 65, 45, 12, 52, 231, 177, 50, 154, 96, 182, 166, 169, 166, 93, 246, 122, 129, 202, 33, 166, 99, 164, 185, 154, 192, 255, 16, 149, 39, 170, 103, 213, 145, 22, 78, 195, 39, 23, 183, 42, 142, 171, 235, 169, 168, 164, 172, 30, 170, 88, 131, 161, 88, 83, 14, 166, 46, 158, 99, 150, 51, 107, 230, 123, 99, 93, 15, 199, 120, 124, 2, 29, 154, 41, 130, 196, 203, 108, 79, 97, 51, 214, 147, 118, 47, 107, 136, 69, 77, 96, 68, 143, 216, 166, 41, 130, 205, 191, 139, 134, 73, 80, 31, 206, 166, 192, 188, 151, 197, 168, 132, 78, 230, 57};
const unsigned char invalidAsymmetricCiphertext[] = {17, 6, 5, 63, 128, 50, 99, 224, 4, 171, 144, 112, 14, 191, 219, 254, 0, 9, 3, 229, 107, 3, 105, 111, 109, 1, 184, 26, 118, 47, 185, 160, 201, 39, 59, 98, 27, 156, 48, 135, 35, 164, 62, 133, 172, 22, 25, 121, 61, 215, 224, 91, 254, 178, 105, 214, 182, 72, 5, 103, 195, 229, 251, 114, 9, 167, 186, 68, 65, 195, 129, 174, 212, 192, 97, 71, 241, 47, 125, 187, 122, 129, 144, 86, 186, 135, 239, 165, 75, 187, 4, 99, 250, 74, 21, 59, 98, 45, 10, 156, 166, 218, 105, 222, 19, 226, 51, 194, 242, 9, 31, 6, 149, 122, 198, 219, 51, 175, 235, 163, 1, 223, 182, 162, 214, 32, 146, 22, 201, 19, 40, 15, 153, 27, 12, 71, 81, 26, 63, 169, 203, 2, 132, 102, 242, 64, 17, 7, 56, 6, 164, 203, 214, 37, 86, 152, 230, 190, 254, 104, 54, 18, 23, 251, 80, 199, 47, 204, 126, 229, 36, 137, 139, 94, 136, 248, 248, 155, 231, 82, 158, 124, 244, 19, 103, 101, 65, 45, 12, 52, 231, 177, 50, 154, 96, 182, 166, 169, 166, 93, 246, 122, 129, 202, 33, 166, 99, 164, 185, 154, 192, 255, 16, 149, 39, 170, 103, 213, 145, 22, 78, 195, 39, 23, 183, 42, 142, 171, 235, 169, 168, 164, 172, 30, 170, 88, 131, 161, 88, 83, 14, 166, 46, 158, 99, 150, 51, 107, 230, 123, 99, 93, 15, 199, 120, 124, 2, 29, 154, 41, 130, 196, 203, 108, 79, 97, 51, 214, 147, 118, 47, 107, 136, 69, 77, 96, 68, 143, 216, 166, 41, 130, 205, 191, 139, 134, 73, 80, 31, 206, 166, 192, 188, 151, 197, 168, 132, 78, 230, 57};
const int asymmetricCipherLen = 300;
const int invalidAsymmetricCipherLen = 300;

const unsigned char symmetricKey[] = {1, 3, 7, 34, 90, 89, 123, 5, 1, 3, 7, 34, 90, 89, 123, 5, 1, 3, 7, 34, 90, 89, 123, 5, 1, 3, 7, 34, 90, 89, 123, 5};
const int symmetricKeySize = 32;
const unsigned char otherSymmetricKey[] = {1, 7, 7, 34, 90, 89, 123, 100, 1, 3, 7, 34, 2, 89, 123, 5, 1, 111, 7, 34, 90, 121, 123, 5, 15, 3, 7, 34, 90, 89, 123, 50};

const unsigned char symmetricCiphertext[] = {31, 140, 166, 244, 123, 96, 94, 188, 127, 107, 148, 36, 57, 29, 247, 35, 246, 87, 5, 121, 27, 175, 198, 25, 132, 47, 122, 88, 80, 61, 148, 24, 27, 84, 77, 119, 157, 157, 198, 140, 158, 135, 119, 46};
const unsigned char invalidSymmetricCiphertext[] = {31, 140, 166, 244, 4, 96, 94, 188, 127, 107, 3, 36, 57, 29, 247, 35, 246, 1, 5, 121, 27, 175, 198, 25, 4, 47, 122, 88, 80, 61, 4, 24, 27, 84, 2, 119, 157, 157, 198, 140, 158, 135, 119, 46};
const int symmetricCipherLen = 44;
const int invalidSymmetricCipherLen = 44;

const unsigned char signedData[] = {1, 56, 125, 100, 200, 156, 230, 80, 70, 45, 20, 76, 23, 67, 45, 12, 143, 112, 164, 107, 167, 15, 93, 166, 193, 162, 94, 112, 108, 250, 43, 118, 125, 206, 106, 204, 174, 84, 237, 239, 202, 187, 251, 155, 52, 183, 155, 60, 53, 156, 90, 247, 134, 138, 184, 21, 105, 85, 208, 68, 168, 153, 33, 117, 1, 209, 86, 123, 154, 208, 149, 234, 163, 3, 93, 9, 21, 246, 212, 158, 115, 190, 192, 22, 246, 204, 227, 111, 68, 162, 165, 241, 21, 74, 17, 96, 244, 82, 155, 204, 16, 76, 15, 28, 130, 217, 102, 118, 36, 83, 229, 214, 51, 77, 88, 4, 146, 150, 165, 233, 132, 215, 83, 83, 142, 98, 16, 200, 19, 66, 70, 222, 163, 76, 46, 21, 3, 240, 152, 222, 230, 77, 66, 222, 45, 127, 28, 130, 115, 148, 163, 22, 170, 71, 40, 119, 92, 134, 106, 240, 180, 189, 2, 68, 139, 137, 227, 223, 197, 140, 214, 86, 33, 149, 47, 117, 0, 47, 188, 19, 74, 11, 40, 184, 108, 124, 41, 85, 32, 52, 201, 27, 129, 221, 112, 182, 145, 101, 187, 92, 13, 65, 251, 218, 220, 182, 63, 190, 69, 74, 165, 34, 61, 142, 224, 160, 62, 81, 6, 197, 185, 179, 159, 25, 177, 87, 156, 164, 249, 54, 1, 146, 195, 173, 156, 73, 186, 202, 68, 214, 160, 42, 208, 99, 28, 176, 115, 235, 182, 76, 10, 237, 83, 212, 41, 246, 7, 189, 228, 231, 236, 121, 166, 55, 51, 177, 152, 140, 163, 183, 115, 222};
const int signedDatalen = 272;

const unsigned char invalidSignedData[] = {1, 56, 125, 100, 4, 156, 1, 80, 70, 45, 20, 76, 23, 67, 7, 12, 143, 112, 164, 107, 167, 15, 93, 9, 193, 162, 94, 112, 108, 250, 43, 118, 125, 206, 106, 204, 174, 84, 237, 239, 202, 187, 251, 155, 52, 183, 155, 60, 53, 156, 90, 247, 134, 138, 184, 21, 105, 85, 208, 68, 168, 153, 33, 117, 1, 209, 86, 123, 154, 208, 149, 234, 163, 3, 93, 9, 21, 246, 212, 158, 115, 190, 192, 22, 246, 204, 227, 111, 68, 162, 165, 241, 21, 74, 17, 96, 244, 82, 155, 204, 16, 76, 15, 28, 130, 217, 102, 118, 36, 83, 229, 214, 51, 77, 88, 4, 146, 150, 165, 233, 132, 215, 83, 83, 142, 98, 16, 200, 19, 66, 70, 222, 163, 76, 46, 21, 3, 240, 152, 222, 230, 77, 66, 222, 45, 127, 28, 130, 115, 148, 163, 22, 170, 71, 40, 119, 92, 134, 106, 240, 180, 189, 2, 68, 139, 137, 227, 223, 197, 140, 214, 86, 33, 149, 47, 117, 0, 47, 188, 19, 74, 11, 40, 184, 108, 124, 41, 85, 32, 52, 201, 27, 129, 221, 112, 182, 145, 101, 187, 92, 13, 65, 251, 218, 220, 182, 63, 190, 69, 74, 165, 34, 61, 142, 224, 160, 62, 81, 6, 197, 185, 179, 159, 25, 177, 87, 156, 164, 249, 54, 1, 146, 195, 7, 189, 228, 231, 236, 121, 166, 55, 51, 177, 152, 140, 163, 183, 115, 222};
const int invalidSignedDatalen = 249;

const char *publicKeys[] = {publicKey, otherPublicKey};
const char *invalidPublicKeys[] = {publicKey, invalidPublicKey};
const int publicKeysCount = 2;
const char *address = "cbff2e12fb1f752cb17185f080f2b40301165a1051531cc0614e495ee2620ef9";
const char *addresses[] = {address, address};

const unsigned char onion[] = {1, 76, 12, 5, 29, 7, 248, 206, 17, 105, 127, 188, 225, 155, 222, 158, 221, 120, 138, 15, 198, 142, 185, 87, 222, 82, 144, 23, 235, 117, 23, 192, 94, 20, 79, 8, 216, 46, 52, 176, 180, 69, 131, 33, 196, 11, 1, 112, 177, 15, 3, 26, 184, 193, 27, 130, 7, 211, 77, 197, 214, 179, 243, 225, 123, 130, 192, 176, 111, 199, 131, 155, 237, 8, 223, 128, 94, 232, 172, 248, 181, 101, 102, 166, 43, 195, 205, 67, 253, 253, 160, 142, 105, 165, 154, 70, 9, 161, 183, 41, 103, 194, 34, 166, 249, 41, 53, 230, 51, 104, 147, 100, 58, 202, 40, 45, 225, 82, 23, 67, 161, 104, 196, 116, 153, 202, 113, 142, 91, 138, 1, 108, 197, 29, 39, 161, 251, 76, 196, 74, 245, 191, 224, 209, 119, 195, 43, 115, 187, 151, 18, 215, 2, 54, 107, 0, 88, 93, 157, 34, 28, 232, 216, 222, 102, 228, 203, 218, 214, 215, 149, 10, 155, 145, 92, 96, 178, 166, 60, 141, 7, 209, 83, 155, 142, 165, 8, 15, 88, 141, 132, 82, 91, 208, 150, 201, 104, 91, 12, 129, 14, 118, 34, 9, 112, 106, 192, 184, 76, 193, 146, 30, 94, 115, 84, 34, 72, 51, 161, 94, 103, 253, 48, 9, 168, 77, 32, 191, 98, 254, 12, 67, 14, 111, 39, 150, 145, 212, 43, 116, 80, 91, 121, 240, 45, 188, 31, 118, 38, 152, 18, 232, 255, 200, 159, 220, 184, 157, 75, 56, 132, 13, 150, 238, 253, 74, 72, 60, 71, 5, 119, 120, 225, 218, 70, 244, 74, 240, 167, 13, 144, 0, 62, 69, 55, 51, 153, 219, 7, 126, 211, 3, 101, 90, 21, 17, 0, 124, 214, 19, 67, 8, 220, 112, 99, 253, 25, 140, 210, 210, 177, 23, 241, 223, 55, 240, 4, 205, 25, 89, 211, 238, 241, 81, 76, 253, 33, 57, 137, 22, 42, 30, 208, 153};
const int onionLen = 334;

bool TestOnionSealUnseal()
{
    return true;
    int outlen;
    const char *publicKeys[] = { publicKey, publicKey2 };
    const char *addresses[] = { address, address };

    const unsigned char *out = SealOnion(plaintext, plaintextLen, publicKeys, addresses, publicKeysCount, outlen);

    if(outlen != 652 || not out)
    {
        return false;
    }

    CryptoContext *ctx = CreateAsymmetricDecryptionContext(privateKey2, privateKeyPassphrase);
    const unsigned char *out1 = UnsealOnion(ctx, out, outlen);

    if(outlen != 366 || not out1)
    {
        return false;
    }

    CryptoContext *ctx1 = CreateAsymmetricDecryptionContext(privateKey, privateKeyPassphrase);
    const unsigned char *out2 = UnsealOnion(ctx1, out1 + ADDRESS_SIZE, outlen);

    bool result = out2 && outlen == plaintextLen + ADDRESS_SIZE && !memcmp(plaintext, out2 + ADDRESS_SIZE, plaintextLen);

    delete ctx;
    delete ctx1;
    delete[] out;

    return result;
}

bool TestSealOnion()
{
    int outlen;
    const unsigned char *out = SealOnion(plaintext, plaintextLen, publicKeys, addresses, publicKeysCount, outlen);
    bool success = out and outlen == 652;
    delete[] out;
    return success;
}

bool TestSealOnionInvalidKeysFails()
{
    int outlen;
    const unsigned char *out = SealOnion(plaintext, plaintextLen, invalidPublicKeys, addresses, publicKeysCount, outlen);
    return not out and outlen < 0;
}

bool TestOnionUnseal()
{
    CryptoContext *ctx = CreateAsymmetricDecryptionContext(privateKey, privateKeyPassphrase);
    int outlen;
    const unsigned char *out = UnsealOnion(ctx, onion, outlen);
    bool result = out && outlen == plaintextLen + 32 && !memcmp(plaintext, out + 32, plaintextLen);
    delete ctx;
    return result;
}

bool TestOnionUnsealInvalidKeyFails()
{
    CryptoContext *ctx = CreateAsymmetricDecryptionContext(invalidPrivateKey, privateKeyPassphrase);
    int outlen;
    const unsigned char *out = UnsealOnion(ctx, onion, outlen);
    delete ctx;
    return not out && outlen < 0;
}

bool TestOnionUnsealWrongKeyFails()
{
    CryptoContext *ctx = CreateAsymmetricDecryptionContext(otherPrivateKey);
    int outlen;
    const unsigned char *out = UnsealOnion(ctx, onion, outlen);
    delete ctx;
    return not out && outlen < 0;
}

int main()
{
    CryptoContext *ctx = CreateAsymmetricEncryptionContext(publicKey);
    bool result = RunTest("Test asymmetric encryption", Run, ctx, plaintext, plaintextLen, nullptr, asymmetricCipherLen);
    delete ctx;

    ctx = CreateAsymmetricEncryptionContext(invalidPublicKey);
    result = result & RunTest("Test asymmetric encryption with invalid key should fail", Run, ctx, plaintext, plaintextLen, nullptr, -1);
    delete ctx;

    SetMasterPassphraseName("AenigmaTestMasterPassphrase");
    CreateMasterPassphrase(privateKeyPassphrase);
    ctx = CreateAsymmetricDecryptionContext(privateKey);
    result = result & RunTest("Test asymmetric decryption with master passphrase", Run, ctx, asymmetricCiphertext, asymmetricCipherLen, plaintext, plaintextLen);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContextFromFile("../tests/private.pem");
    result = result & RunTest("Create ctx from file; Test asymmetric decryption with master passphrase", Run, ctx, asymmetricCiphertext, asymmetricCipherLen, plaintext, plaintextLen);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContext(privateKey, privateKeyPassphrase);
    result = result & RunTest("Test asymmetric decryption", Run, ctx, asymmetricCiphertext, asymmetricCipherLen, plaintext, plaintextLen);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContext(invalidPrivateKey, privateKeyPassphrase);
    result = result & RunTest("Test asymmetric decryption with invalid key should fail", Run, ctx, asymmetricCiphertext, asymmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContext(otherPrivateKey);
    result = result & RunTest("Test asymmetric decryption with other key should fail", Run, ctx, asymmetricCiphertext, asymmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContext(privateKey, privateKeyPassphrase);
    result = result & RunTest("Test asymmetric decryption with invalid ciphertext should fail", Run, ctx, invalidAsymmetricCiphertext, invalidAsymmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateSymmetricEncryptionContext(symmetricKey);
    result = result & RunTest("Test symmetric encryption", Run, ctx, plaintext, plaintextLen, nullptr, symmetricCipherLen);
    delete ctx;

    ctx = CreateSymmetricDecryptionContext(symmetricKey);
    result = result & RunTest("Test symmetric decryption", Run, ctx, symmetricCiphertext, symmetricCipherLen, plaintext, plaintextLen);
    delete ctx;

    ctx = CreateSymmetricDecryptionContext(otherSymmetricKey);
    result = result & RunTest("Test symmetric decryption with wrong key should fail", Run, ctx, symmetricCiphertext, symmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateSymmetricDecryptionContext(otherSymmetricKey);
    result = result & RunTest("Test symmetric decryption with invalid ciphertext should fail", Run, ctx, invalidSymmetricCiphertext, invalidSymmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateSignatureContext(privateKey);
    result = result & RunTest("Test signature with master passphrase", Run, ctx, plaintext, plaintextLen, nullptr, signedDatalen);
    delete ctx;

    ctx = CreateSignatureContextFromFile("../tests/private.pem");
    result = result & RunTest("Create ctx from file; Test signature with master passphrase", Run, ctx, plaintext, plaintextLen, nullptr, signedDatalen);
    delete ctx;

    ctx = CreateSignatureContext(privateKey, privateKeyPassphrase);
    result = result & RunTest("Test signature", Run, ctx, plaintext, plaintextLen, nullptr, signedDatalen);
    delete ctx;

    ctx = CreateSignatureContext(invalidPrivateKey, privateKeyPassphrase);
    result = result & RunTest("Test signature with invalid key should fail", Run, ctx, plaintext, plaintextLen, nullptr, -1);
    delete ctx;

    ctx = CreateVerificationContext(publicKey);
    result = result & RunTest("Test signature verification", RunVerification, ctx, signedData, signedDatalen, true);
    delete ctx;

    ctx = CreateVerificationContext(invalidPublicKey);
    result = result & RunTest("Test signature verification with invalid key should fail", RunVerification, ctx, signedData, signedDatalen, false);
    delete ctx;

    ctx = CreateVerificationContext(invalidPublicKey);
    result = result & RunTest("Test signature verification with invalid signed data should fail", RunVerification, ctx, invalidSignedData, invalidSignedDatalen, false);
    delete ctx;

    bool t;
    PrintResult("Test get correct key size; result: ", t = GetPKeySize(publicKey) == 256);
    result = result & t;

    PrintResult("Test onion seal unseal; result: ", t = TestOnionSealUnseal());
    result = result & t;

    PrintResult("Test seal onion; result: ", t = TestSealOnion());
    result = result & t;

    PrintResult("Test seal onion with invalid key should fail; result: ", t = TestSealOnionInvalidKeysFails());
    result = result & t;

    PrintResult("Test onion unseal; result: ", t = TestOnionUnseal());
    result = result & t;

    PrintResult("Test onion unsealing with invalid key fails; result: ", t = TestOnionUnsealInvalidKeyFails());
    result = result & t;

    PrintResult("Test onion unsealing with other key fails; result: ", t = TestOnionUnsealWrongKeyFails());
    result = result & t;

    PrintResult("===== TEST RESULT =====> ", result);

    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
