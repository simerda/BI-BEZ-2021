#include <iostream>
#include <cstring>
#include <stdexcept>
#include <fstream>
#include <cmath>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

const size_t MINIMUM_FILE_BUFFER_SIZE = 1024;

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

int main(int argc, char *argv[])
{
    if(argc < 3){
        cout << "Too few arguments." << endl;
        return 1;
    }

    if(argc > 3){
        cout << "Too many arguments." << endl;
        return 2;
    }

    string privKey(argv[1]);
    string inFile(argv[2]);

    try{
        SealDecryptor decryptor(privKey, inFile);
        decryptor.decryptFile(inFile + "_opened");
    } catch (const exception &e) {
        cout << "Error: " << e.what() << endl;
        return 3;
    }

    return 0;
}
