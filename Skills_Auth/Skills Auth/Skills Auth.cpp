#include <iostream>
#include <string>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

class S3Authenticator {
private:
    std::string accessKeyId;
    std::string secretAccessKey;
public:
    S3Authenticator(const std::string& accessKeyId, const std::string& secretAccessKey) : accessKeyId(accessKeyId), secretAccessKey(secretAccessKey) {}

    std::string generateSignature(const std::string& stringToSign) {
        unsigned int result_len;
        unsigned char* result = HMAC(EVP_sha256(), secretAccessKey.c_str(), secretAccessKey.size(), reinterpret_cast<const unsigned char*>(stringToSign.c_str()), stringToSign.size(), NULL, &result_len);

        BIO* bio = BIO_new(BIO_s_mem());
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, result, result_len);
        BIO_flush(bio);

        BUF_MEM* bptr;
        BIO_get_mem_ptr(bio, &bptr);

        std::string signature(bptr->data, bptr->length);

        BIO_free(bio);
        delete[] result;

        return signature;
    }

    std::string signRequest(const std::string& method, const std::string& contentMd5, const std::string& contentType, const std::string& date, const std::string& canonicalizedHeaders, const std::string& canonicalizedResource) {
        std::string stringToSign = method + "\n" + contentMd5 + "\n" + contentType + "\n" + date + "\n" + canonicalizedHeaders + canonicalizedResource;
        std::string signature = generateSignature(stringToSign);

        return signature;
    }
};

int main() {
    std::string accessKeyId = "your-access-key-id";
    std::string secretAccessKey = "your-secret-access-key";

    S3Authenticator authenticator(accessKeyId, secretAccessKey);

    std::string method = "GET";
    std::string contentMd5 = "";
    std::string contentType = "";
    std::string date = "Mon, 1 Jan 2023 00:00:00 GMT";
    std::string canonicalizedHeaders = "";
    std::string canonicalizedResource = "/your-bucket/your-object";

    std::string signature = authenticator.signRequest(method, contentMd5, contentType, date, canonicalizedHeaders, canonicalizedResource);

    std::cout << "Signature: " << signature << std::endl;

    return 0;
}
