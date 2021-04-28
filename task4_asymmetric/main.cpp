#include <iostream>
#include <cstring>
#include <stdexcept>
#include <fstream>
#include <cmath>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

const size_t MINIMUM_FILE_BUFFER_SIZE = 1024;

class SealEncryptor {
public:
    SealEncryptor(const string &cipherStr, const string &publicKeyPath)
    {
        context = EVP_CIPHER_CTX_new();
        cipher = EVP_get_cipherbyname(cipherStr.c_str());

        if (!context) {
            throw runtime_error("Failed to initialize context.");
        }

        if (!cipher) {
            throw invalid_argument("Invalid cipherStr name.");
        }
        // set file buffer size as next greater or equal number that is divisible by cipherStr block size
        fileBufferSize = (int) ceil( // NOLINT(cppcoreguidelines-narrowing-conversions)
                MINIMUM_FILE_BUFFER_SIZE / (double) EVP_CIPHER_block_size(cipher)
                ) * EVP_CIPHER_block_size(cipher);

        FILE *pubKeyFile = fopen(publicKeyPath.c_str(), "rt");
        if (!pubKeyFile) {
            throw runtime_error("Could not open file with public key.");
        }

        publicKey = PEM_read_PUBKEY(pubKeyFile, nullptr, nullptr, nullptr);
        fclose(pubKeyFile);
        if (!publicKey) {
            throw invalid_argument("Could not read public key.");
        }
        encryptedKeyBufferSize = EVP_PKEY_size(publicKey);
        encryptedKey = new unsigned char[encryptedKeyBufferSize];

        ivLength = EVP_CIPHER_iv_length(cipher);
        if(ivLength > 0){
            iv = new unsigned char[ivLength];
        }

        // initialize seal
        int outcome = EVP_SealInit(
                context,
                cipher,
                &encryptedKey,
                &encryptedKeyBufferSize,
                iv,
                &publicKey,
                1
        );

        if(outcome != 1){
            delete[] iv;
            delete[] encryptedKey;
            throw runtime_error("Failed to initialize EVP seal.");
        }

        // trim encrypted key
        auto tmp = new unsigned char[encryptedKeyBufferSize];
        memcpy(tmp, encryptedKey, encryptedKeyBufferSize);
        delete[] encryptedKey;
        encryptedKey = tmp;

    }

    ~SealEncryptor()
    {
        EVP_CIPHER_CTX_free(context);
        EVP_PKEY_free(publicKey);
        delete[] encryptedKey;
        delete[] iv;
        delete[] inBuffer;
        delete[] outBuffer;
    }


    void encryptFile(const string &path)
    {
        ifstream inputFile;
        inputFile.open(path, ios_base::in | ios_base::binary);

        ofstream outputFile;
        outputFile.open(path + "_seal", ios_base::out | ios_base::binary);

        int nid = EVP_CIPHER_nid(cipher);
        outputFile.write(reinterpret_cast<char *>(&nid), sizeof(nid));
        outputFile.write(reinterpret_cast<char *>(&encryptedKeyBufferSize), sizeof(encryptedKeyBufferSize));
        outputFile.write(reinterpret_cast<char *>(encryptedKey), encryptedKeyBufferSize);
        if(iv != nullptr){
            outputFile.write(reinterpret_cast<char *>(iv), ivLength);
        }

        inBuffer = new unsigned char[fileBufferSize];
        outBuffer = new unsigned char[fileBufferSize];
        do{
            inputFile.read(reinterpret_cast<char *>(inBuffer), fileBufferSize);
            streamsize bytesRead = inputFile.gcount();
            if(bytesRead <= 0){
                break;
            }

            if(EVP_SealUpdate(context, outBuffer, &fileBufferSize, inBuffer, bytesRead) != 1){
                throw runtime_error("Failed to encrypt.");
            }

            outputFile.write(reinterpret_cast<char *>(outBuffer), fileBufferSize);
        }while(inputFile);

        if(! inputFile.eof()){
            throw runtime_error("Failed reading from file.");
        }

        int written;
        if(EVP_SealFinal(context, outBuffer, &written) != 1){
            throw runtime_error("Failed to encrypt.");
        }

        outputFile.write(reinterpret_cast<char *>(outBuffer), written);
        if(! outputFile){
            throw runtime_error("Failed to write encrypted data.");
        }
    }

private:
    EVP_CIPHER_CTX *context = nullptr;
    const EVP_CIPHER *cipher = nullptr;
    EVP_PKEY *publicKey = nullptr;
    unsigned char *encryptedKey = nullptr;
    int encryptedKeyBufferSize;
    unsigned char *iv = nullptr;
    int ivLength;
    int fileBufferSize;
    unsigned char *inBuffer = nullptr;
    unsigned char *outBuffer = nullptr;
};


class SealDecryptor {
public:
    SealDecryptor(const string &privateKeyPath, const string &sealedPath)
    {
        EVP_PKEY *privateKey = nullptr;
        FILE *privKeyFile = fopen(privateKeyPath.c_str(), "rt");
        if (!privKeyFile) {
            throw runtime_error("Could not open file with private key.");
        }
        privateKey = PEM_read_PrivateKey(privKeyFile, nullptr, nullptr, nullptr);
        fclose(privKeyFile);
        if (!privateKey) {
            throw invalid_argument("Could not read private key.");
        }

        inputFile.open(sealedPath, ios_base::in | ios_base::binary);
        int nid;
        inputFile.read(reinterpret_cast<char *>(&nid), sizeof(nid));

        if(! inputFile){
            EVP_PKEY_free(privateKey);
            throw invalid_argument("Failed to read sealed file.");
        }

        const EVP_CIPHER *cipher = EVP_get_cipherbynid(nid);
        if(!cipher){
            EVP_PKEY_free(privateKey);
            throw invalid_argument("Provided sealed file is invalid.");
        }

        int encryptedKeyLength;
        inputFile.read(reinterpret_cast<char *>(&encryptedKeyLength), sizeof(encryptedKeyLength));
        if(encryptedKeyLength <= 0 || encryptedKeyLength >= 10000){
            EVP_PKEY_free(privateKey);
            throw invalid_argument("Provided sealed file is invalid.");
        }
        auto encryptedKey = new unsigned char[encryptedKeyLength];
        inputFile.read(reinterpret_cast<char *>(encryptedKey), encryptedKeyLength);

        int ivLength = EVP_CIPHER_iv_length(cipher);
        unsigned char *iv = nullptr;

        if(ivLength > 0){
            iv = new unsigned char[ivLength];
            inputFile.read(reinterpret_cast<char *>(iv), ivLength);
        }

        if(! inputFile){
            EVP_PKEY_free(privateKey);
            throw runtime_error("Provided sealed file is invalid.");
        }

        context = EVP_CIPHER_CTX_new();
        int outcome = EVP_OpenInit(context, cipher, encryptedKey, encryptedKeyLength, iv, privateKey);
        EVP_PKEY_free(privateKey);

        if(outcome != 1){
            throw runtime_error("Failed to initialize EVP open.");
        }

        // set file buffer size as next greater or equal number that is divisible by cipherStr block size
        fileBufferSize = (int) ceil( // NOLINT(cppcoreguidelines-narrowing-conversions)
                MINIMUM_FILE_BUFFER_SIZE / (double) EVP_CIPHER_block_size(cipher)
        ) * EVP_CIPHER_block_size(cipher);
        delete[] iv;
        delete[] encryptedKey;
    }

    ~SealDecryptor()
    {
        EVP_CIPHER_CTX_free(context);
        delete[] inBuffer;
        delete[] outBuffer;
    }


    void decryptFile(const string &path)
    {
        ofstream outputFile;
        outputFile.open(path, ios_base::out | ios_base::binary);
        if(! outputFile){
            throw runtime_error("Failed to open output file.");
        }

        inBuffer = new unsigned char[fileBufferSize];
        outBuffer = new unsigned char[fileBufferSize];
        do{
            inputFile.read(reinterpret_cast<char *>(inBuffer), fileBufferSize);
            streamsize bytesRead = inputFile.gcount();
            if(bytesRead <= 0){
                break;
            }

            if(EVP_OpenUpdate(context, outBuffer, &fileBufferSize, inBuffer, bytesRead) != 1){
                throw runtime_error("Failed to decrypt.");
            }

            outputFile.write(reinterpret_cast<char *>(outBuffer), fileBufferSize);
        }while(inputFile);

        if(! inputFile.eof()){
            throw runtime_error("Failed reading from file.");
        }

        int written;
        if(EVP_OpenFinal(context, outBuffer, &written) != 1){
            throw runtime_error("Failed to decrypt.");
        }

        outputFile.write(reinterpret_cast<char *>(outBuffer), written);
        if(! outputFile){
            throw runtime_error("Failed to write decrypted data.");
        }
    }


private:
    ifstream inputFile;
    EVP_CIPHER_CTX *context = nullptr;
    int fileBufferSize;
    unsigned char *inBuffer;
    unsigned char *outBuffer;
};

int main()
{
    SealEncryptor encryptor("aria-128-cfb8", "/home/simerjan/projects/cvut/BEZ/repo/task4_asymmetric/pubkey.pem");
    encryptor.encryptFile("/home/simerjan/Downloads/mariadb.sql");

    SealDecryptor decryptor("/home/simerjan/projects/cvut/BEZ/repo/task4_asymmetric/privkey.pem", "/home/simerjan/Downloads/mariadb.sql_seal");
    decryptor.decryptFile("/home/simerjan/Downloads/mariadb.sql_unsealed");

    return 0;
}
