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
    cout << message << (success ? "\033[32m" : "\033[31m") << "SUCCESS" << "\033[0m;\n";
}

bool RunTest(const char *testCase, EncryptionFunction executor, CryptoContext *ctx, const unsigned char *input, unsigned int inlen, const unsigned char *expectedOutput, int expectedOutlen)
{
    cout << testCase << ";";
    bool success = TestSubsequentOperations(executor, ctx, input, inlen, expectedOutput, expectedOutlen);
    PrintResult("result: ", success);
    return success;
}

bool RunTest(const char *testCase, VerificationFunction executor, CryptoContext *ctx, const unsigned char *input, unsigned int inlen, bool expectedResult)
{
    cout << testCase << ";";
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

int main()
{
    CryptoContext *ctx = CreateAsymmetricEncryptionContext(publicKey);
    bool result = RunTest("Test asymmetric encryption", EncryptData, ctx, plaintext, plaintextLen, nullptr, asymmetricCipherLen);
    delete ctx;

    ctx = CreateAsymmetricEncryptionContext(invalidPublicKey);
    result = result && RunTest("Test asymmetric encryption with invalid key should fail", EncryptData, ctx, plaintext, plaintextLen, nullptr, -1);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContext(privateKey, privateKeyPassphrase);
    result = result && RunTest("Test asymmetric decryption", DecryptData, ctx, asymmetricCiphertext, asymmetricCipherLen, plaintext, plaintextLen);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContext(invalidPrivateKey, privateKeyPassphrase);
    result = result && RunTest("Test asymmetric decryption with invalid key should fail", DecryptData, ctx, asymmetricCiphertext, asymmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContext(otherPrivateKey);
    result = result && RunTest("Test asymmetric decryption with other key should fail", DecryptData, ctx, asymmetricCiphertext, asymmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateAsymmetricDecryptionContext(privateKey, privateKeyPassphrase);
    result = result && RunTest("Test asymmetric decryption with invalid ciphertext should fail", DecryptData, ctx, invalidAsymmetricCiphertext, invalidAsymmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateSymmetricEncryptionContext(symmetricKey);
    result = result && RunTest("Test symmetric encryption", EncryptData, ctx, plaintext, plaintextLen, nullptr, symmetricCipherLen);
    delete ctx;

    ctx = CreateSymmetricDecryptionContext(symmetricKey);
    result = result && RunTest("Test symmetric decryption", DecryptData, ctx, symmetricCiphertext, symmetricCipherLen, plaintext, plaintextLen);
    delete ctx;

    ctx = CreateSymmetricDecryptionContext(otherSymmetricKey);
    result = result && RunTest("Test symmetric decryption with wrong key should fail", DecryptData, ctx, symmetricCiphertext, symmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateSymmetricDecryptionContext(otherSymmetricKey);
    result = result && RunTest("Test symmetric decryption with invalid ciphertext should fail", DecryptData, ctx, invalidSymmetricCiphertext, invalidSymmetricCipherLen, nullptr, -1);
    delete ctx;

    ctx = CreateSignatureContext(privateKey, privateKeyPassphrase);
    result = result && RunTest("Test signature", SignData, ctx, plaintext, plaintextLen, nullptr, signedDatalen);
    delete ctx;

    ctx = CreateSignatureContext(invalidPrivateKey, privateKeyPassphrase);
    result = result && RunTest("Test signature with invalid key should fail", SignData, ctx, plaintext, plaintextLen, nullptr, -1);
    delete ctx;

    ctx = CreateVerificationContext(publicKey);
    result = result && RunTest("Test signature verification", VerifySignature, ctx, signedData, signedDatalen, true);
    delete ctx;

    ctx = CreateVerificationContext(invalidPublicKey);
    result = result && RunTest("Test signature verification with invalid key should fail", VerifySignature, ctx, signedData, signedDatalen, false);
    delete ctx;

    ctx = CreateVerificationContext(invalidPublicKey);
    result = result && RunTest("Test signature verification with invalid signed data should fail", VerifySignature, ctx, invalidSignedData, invalidSignedDatalen, false);
    delete ctx;

    PrintResult("===== TEST RESULT =====> ", result);

    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}
