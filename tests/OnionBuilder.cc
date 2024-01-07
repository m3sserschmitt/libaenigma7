#include "cryptography/Libcryptography.hh"

#include <iostream>

using namespace std;

const char *publicKey1 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9mZB83nnrzpFeSkkr8au\n"
    "1rmcYJhpyikM+4jCdJ5FowumVQ8Rq3yaYVTuz4mFQVyM28BldwXpG3FiL/aM7FHC\n"
    "0H2tbJ/d4sB579WeGBELiHDWVvM5DrOfj/7QroFNDA6gI7Vmvk6o0BBQ+LiIeWTr\n"
    "ivTUTkjZWoTo30RluPEpQKOxRoCdk+DaZNw0FBTdWUngkV8FjHQl6ObWWfQ7f3+t\n"
    "yxMFHD9vMDP+nGXmd4NsnsDMABZ4Yn0rgyW1CF9phB1zLdOgxW+JNjK6wLbCqIyK\n"
    "GCfJFnZpaImguAjdjPG318nXARZ4PqH3LbrYzPPanHz8IVGWA4vt1BlDROGmx8vJ\n"
    "dwIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

const char *publicKey2 =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA13pyOqfbBfDP1HrCyxMw\n"
    "ORgQBEsIfkN3CF6zsSUbydUdKRvs5UvDCDptrQ3y+ThsI5yXwgQyCcaiXCn+5Yzf\n"
    "oD8j6r72EmGPUzOTJs3ZBLe7Dcsk1cOH4wTTH2HMsJ/2BKcfb0o2SK5VCUr/2LE1\n"
    "FQtj7eoA/7yfivxNwnRz+MsyX90pme1uoZsHDBFNijSuvVnERpXkgzCRqC6bwYl2\n"
    "Adbv52GFYcMITM9okZclUHwXIOOAVGtQax7/XCNoCCOcFY2YWPex1+iSPMfyfg6C\n"
    "uJxKtNdBZ4LL19uJSHjz18KJZEpUQ4lSHhiw8usLN4mb6cgx7tXJhr1sE5b9yDK3\n"
    "ZQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

const char *address1 = "cbff2e12fb1f752cb17185f080f2b40301165a1051531cc0614e495ee2620ef9";

const char *address2 = "a186a6fba0ff7570b116b3df639e3713fab0a21f1cf62fb616d84c19217c8023";

const char *privateKey1 =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIsEI2eqZjSp4CAggA\n"
    "MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECLyd3ZG7WbPGBIIEyHYSjK0lFqTh\n"
    "bVqE8wJv/acx5hzGx54Bgk2z9WqlzPH47aRRRIwd0C8/hxk2zgDlmKWPysuzeoh5\n"
    "+ABe7JxTmBZa6BAK2e6Rjz5D82epRQjTeJcgUE8o5V601afBCHzexb7DGvTAqCrB\n"
    "iTmv1OycSW8LP5LkVbdposZOFIaA7hdH+jaJpxhhWLmlcZAzfbFrBsmGheiOpj40\n"
    "m9Ff1ggmKYHn+aoDe5BOaOEvZEDFAmiNorpSUvnjgZdkYu8Hpb/L1pCm4M0aiYei\n"
    "Mwb/IzW8gNdWmHnJAjLYYXWSngQlLEDrHNzrE6o8R4/hgcg2zMttCC3kaTr1EtyQ\n"
    "A2eBnSEj4Jr3SokVlnnI/JwUFY82M29X3uJYsxEPoT5Bj/pOot9C1elFpTDw0uja\n"
    "DU1rsTXHNekHjvHtTaMdlBa8xzqRHlVmmNHS3li5vZw1zgx2JIBAKSE4y8nqwu44\n"
    "9e4yfiwQ6SAxHNalZVralfEUWLJtjUCk5nRe38SZ5+6VAETExUIHSzO+abM/4ieb\n"
    "2skHtqE85vQu0tiXeR/6kBZFAnPETdZRlT3RyDtG3Iq8FPEBFuRwluRpv3/RqcG4\n"
    "zxwfTOL9P/tsMlJ4E5Jsv/7eVrM6QU/aQ545150utiD5HK7QX9PrNdSpTNmtO3mn\n"
    "vRKJHfLHuxxd8DlcKgrs/zoRR0SaI5Ra2kWaarfeXQP29FV+ljUboilXP2bQZgy8\n"
    "v+wuN1AbJeBVL9AxO2Jy66gtd85fr8x2b7HD6q1tlAhylSSDYLKdZkeNkHQBUEdP\n"
    "vtAYVinWMLUTKsolPTivudQYi+60pSn48QPeIH1Ml6NO9EhJ/4oxG5jjBtwqWuDw\n"
    "gHoRWY4LjOzgAhw94Japovffk0EbcYlaH6bwfei73Sj9gcZ37DyQuH9rDvhaU2Rj\n"
    "YIPSdzquVUH8+MsUmpz7jDyGsiygqqixSZ4ozZrXCraq6T3e2T2/uqEDDRIVbnvf\n"
    "UlqoZsV3KPUPmrvc20Twk5t/sCe6dSAeLcr96oOjyHzfng70SxNKZgE0OInaHGKt\n"
    "OY22hmoZpnvoOzL1utnzYFNO675TjdOubECED6w7EnPdetrHY5Vmf5RffggJl66L\n"
    "j66dch3tvJy8pPofGWK/vZdzt4Lx/AL0CnrL8gIM3SSXFDHMd0fyhWfYmFQQHPJ5\n"
    "Em4yuMmdgJgzsmlzeJnNPlT5wl3KNjGMTu3LoPUwMA2hlMR3tCPnO5vFFcQs7cEM\n"
    "+koqtNLrnqcznVUZAZhf2WKBpHxwQ8y5V7g7QuZ0eMeW1+Dv0ARzNG+6pgTsOv57\n"
    "GlgIuBhZXREVJXLctsPWORsbn0q3Xbrtv3gGzldm2EwsFNQ5npFe9o9c0z+waFi+\n"
    "OKK5n8BsRdld90J9HUvl0nJESiITKM88TpD4BW/bNEWMSYEzkASWO2q7mvroXi+A\n"
    "mXZF3HgZBs+96tVMfczw9a+ZuwaxzLsE/8RAPeQg2OAPuVVcDM8v/2zu85gubgKt\n"
    "iEkTGVyd0dimRTpC9fptv0+6bAWED+oRD2reP6hIdLdc1uYTjOzFvv1NhUc7QS+L\n"
    "8kZtCufUYBsXC4ZpAO80ufdsmRA5zOmWCoh1vF1CjcMIFoIIN50GEluNUacQyjpM\n"
    "mtgRHbIakqGM8LmQsak/RA==\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";

const char *privateKey2 =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIyhxEM5lFRTgCAggA\n"
    "MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECNuk2hLDDcqXBIIEyKxZLfd3Z2hf\n"
    "+6XdNIkmEbN0vm1MWIYIVn4g1IiQ17QwKw2sCVfGksA0raF0wOk3cNiu9kYIcaaV\n"
    "O0w+22FBExkGIP0Kx8WKIHcxrLlrzCs7azqFM0+m0aeGibZTNKLolOtlH/JvUJv9\n"
    "i+inoPqiIyyalNeQZsKkGj2SBao+LvnelrRgIdZ4AFsVajgbgRVEakaj+ffXvfP7\n"
    "sZqmaBB1NQLIv+eHZ3HDUKGAU39OrRrlrE4rf0MRmYoNx8FINTz9ATLXak8W6SF8\n"
    "t5QfAXXLtcZemAiVjQMu8UCt0+TrT3P/qar1TomGqx3TjMdeVpKAhIBIqv4i7BcW\n"
    "yek3zzHuwBJ5fn0X/4PfDTqsGwm3wh0zpBNAEJBlAEXtnx6/0kkeRUtWes9U9+Ue\n"
    "/VkWbDhJOtwjHoee2OR4gk41pDR0Q4uJpAwtA71GSkCsFcSW5rzr4+Apb90nYkGC\n"
    "UKLlgeVfPwEoBlvCgDypydO2L4XGpMyDK01K/U0qDX0EEh8+EQfNSfa4GsG+vVS2\n"
    "+2CWRhWQseAJavGTHKsV7QTlpAYbfrchUYoQp8tCq1pXzaqX8YNfWHEX8lLF/+o2\n"
    "rYaroBND1LBgF7P4NsHjoKyn79kMr+r0gZFav+OLlGpTFIgN/1TdjjP/kA5GFbbs\n"
    "zeHqLuGioNhRkzG8uWdt3CnfAXd8b6TMtDHm6gM6vQBw9Oo34aMRaGMJ2A+0uvDZ\n"
    "XoIK3hvm6gE5/Z91V9BQzISyV9vitPpwR3miz/DqJLIGX3U3WYcmZ4xVL+qjjeVi\n"
    "upCUaPtLSpgYpDxyMGY7ZWykx5eQ8F9JU4rx1d4rMANCF7D1Blon+290Kg1zoFyO\n"
    "QI3f+vhQD4qOBiQYJLboNkKBQfhOoZzmHLjMB2fORwBovd08zbDGn9BHKk1bd34x\n"
    "12Bib+LfpruNCr29cyoQqr1K9yKpTSN8IeSrRITisgbUFr0RLQa6jPoJB7ZyVi5u\n"
    "yFUbGy/a+ML34+/hJDPLOugFTiu8TCaiXrMWDDiU75IzAf+K2b4KTne910V0Al/s\n"
    "hppX4PSEVF1cwGKCNY26JetLHTFmDLhJvenvHCYJodxy2XKYSAZCO7x4vYsFXbhY\n"
    "rhTJIGonLmmk4ceSQdxXZ1rIrU2bFSQpyHGbuFJ9Cl6aYfrqgrQVklF7itz5LlyH\n"
    "n/dQ/PQk5VNaxaXztYNDAq9RIdU5Cj86axogswl8mZIWHInLgMe8PLaHU8c2Ui2p\n"
    "DXUpYL5NKlZ381TAffcwkNis/hwg0VQamL5jRlAytyL2Nf60Xe/uEn3VarsvWcgA\n"
    "/ah3WIgZM+mKw/ipg1QHOFPlJeATCtPZ6kAj7wHop95AH9qmZ2RkmmmTa15UDLdh\n"
    "VBsbXaIHgB95C1VVUx7tjZFbZaxM2ioKEsUSzPI+T0WtWy80+otu9tcKJ4pzfb5J\n"
    "OI0WVHc9bNrH7V8NOdCYkWIf4eU6cQicwfiJgv96+zamVMhZoahIiWGSb+PXX+Cj\n"
    "ZDg3AwToyLQF9r5kmH/1l48zJOBCEeRZgmCKRg6BoutwufhFtxBkBoGSmqlqsFRh\n"
    "159oFu3lvySMApH2hsXFM7X1lSRer9DHCYx/taO/IiS8UBV5EKoRV0fknGILZOBA\n"
    "sAjwH0LbWe1xhKWHRXhcvA==\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n";

int main()
{
    const char *keys[] = {publicKey1, publicKey2};

    const char *addresses[] = {address1, address2};

    const unsigned char plaintext[] = {1, 2, 3, 4, 5, 6, 7, 8};

    int outLen;
    const unsigned char *onion = SealOnion(plaintext, 8, keys, addresses, 2, outLen);

    if (outLen < 0 or not onion)
    {
        cout << "Failure!" << endl;
        return -1;
    }

    CryptoContext *ctx1 = CreateAsymmetricDecryptionContext(privateKey2, "12345678");
    CryptoContext *ctx2 = CreateAsymmetricDecryptionContext(privateKey1, "12345678");

    const unsigned char *out1 = UnsealOnion(ctx1, onion, outLen);

    if(not out1 or outLen < 0)
    {
        cout << "Failure!" << endl;
        return -1;
    }

    const unsigned char *out2 = UnsealOnion(ctx2, out1 + GetDefaultAddressSize(), outLen);

    if(not out2 or outLen < 0)
    {
        cout << "Failure!" << endl;
        return -1;
    }

    if(memcmp(out2 + GetDefaultAddressSize(), plaintext, 8) != 0)
    {
        cout << "Failure!" << endl;
        return -1;
    }

    delete[] onion;
    FreeContext(ctx1);
    FreeContext(ctx2);

    cout << "Success!" << endl;

    return 0;
}
