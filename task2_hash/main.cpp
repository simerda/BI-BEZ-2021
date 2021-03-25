#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <openssl/evp.h>

using namespace std;


string computeHash(const vector<unsigned char> &data)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if (!EVP_DigestInit_ex(context, EVP_sha384(), nullptr)){
        exit(1);        // failed to initialize
    }

    for(size_t i = 0; i < data.size(); i++){
        if(!EVP_DigestUpdate(context, &data.at(i), sizeof(data.at(i)))) {
            exit(2);    // failed to update
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length;

    if(!EVP_DigestFinal_ex(context, hash, &length)){
        exit(3);        // failed to finalize
    }

    EVP_MD_CTX_free(context);

    return string(reinterpret_cast<const char *>(hash), length);
}

void printHalfByte(unsigned char byte)
{
    if(byte < 10){
        cout << (unsigned char) ((int)'0' + (int)byte) << flush;
    }else{
        cout << (unsigned char) ((int) 'A' + (int) byte - 10) << flush;
    }
}

void printHash(const string &hash)
{
    for(unsigned char byte : hash){

        printHalfByte(byte >> 4);
        printHalfByte(byte & 0xF);
    }

    cout << endl;
}

void printInput(const vector<unsigned char> &data)
{
    for(unsigned char byte : data){

        printHalfByte(byte >> 4);
        printHalfByte(byte & 0xF);
    }

    cout << endl;
}

bool passes(const string &hash, size_t zeroBitsCount)
{
    if(zeroBitsCount <= 0){
        return true;
    }

    if(zeroBitsCount > hash.size() * sizeof(unsigned char)){
        return false;
    }

    size_t zeroBits = 0;
    for(unsigned char byte : hash){

        for(int i = 7; i >= 0; i--){

            if((byte >> i) & 1){
                return false;
            }

            if(++zeroBits >= zeroBitsCount){
                return true;
            }
        }


    }

    return false;
}


int main(int argc, char *argv[])
{
    if(argc <= 1){
        cout << "Too few arguments." << endl;
        return 4;
    }

    if(argc > 2){
        cout << "Too many arguments." << endl;
        return 5;
    }
    size_t numberOfZeros;
    istringstream argStream(argv[1]);
    argStream >> numberOfZeros;

    if(!argStream.good() && !argStream.eof()){
        cout << "Failed to parse argument." << endl;
        return 6;
    }

    OpenSSL_add_all_digests();

    vector<unsigned char> data;
    data.push_back(0);

    size_t currIndex = 0;
    string hash;
    do{
        if(data.at(currIndex) == 0xFF){
            currIndex++;
        }

        if(currIndex >= data.size()){
            for(unsigned char & i : data){
                i = 0;
            }
            data.push_back(0);
            currIndex = 0;
        }

        hash = computeHash(data);

        if(passes(hash, numberOfZeros)){
            break;
        }

        data[currIndex]++;
    }while(true);

    cout << "Input:" << endl;
    printInput(data);

    cout << "Hash:" << endl;
    printHash(hash);

    return 0;
}
