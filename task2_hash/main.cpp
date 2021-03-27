#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <openssl/evp.h>

using namespace std;


class Hasher {
public:
    Hasher()
    {
        OpenSSL_add_all_digests();
        context = EVP_MD_CTX_new();
    }

    ~Hasher()
    {
        EVP_MD_CTX_free(context);
    }

    string computeHash(const vector<unsigned char> &data)
    {
        if (!EVP_DigestInit_ex(context, EVP_sha384(), nullptr)) {
            throw runtime_error("Failed to initialize hash context.");
        }

        for (size_t i = 0; i < data.size(); i++) {
            if (!EVP_DigestUpdate(context, &data.at(i), sizeof(data.at(i)))) {
                throw runtime_error("Failed to update hash context.");
            }
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int length;

        if (!EVP_DigestFinal_ex(context, hash, &length)) {
            throw runtime_error("Failed to finalize hash context.");
        }

        return string(reinterpret_cast<const char *>(hash), length);
    }

private:
    EVP_MD_CTX *context;
};


void printHalfByte(unsigned char byte)
{
    if (byte < 10) {
        cout << (char) ('0' + byte) << flush;
    } else {
        cout << (char) ('A' + byte - 10) << flush;
    }
}

void printHash(const string &hash)
{
    for (unsigned char byte : hash) {

        printHalfByte(byte >> 4);
        printHalfByte(byte & 0xF);
    }

    cout << endl;
}

void printInput(const vector<unsigned char> &data)
{
    for (unsigned char byte : data) {

        printHalfByte(byte >> 4);
        printHalfByte(byte & 0xF);
    }

    cout << endl;
}

bool passes(const string &hash, size_t zeroBitsCount)
{
    if (zeroBitsCount <= 0) {
        return true;
    }

    if (zeroBitsCount > hash.size() * sizeof(unsigned char) * 8) {
        throw invalid_argument("Given zero count is greater than total hash size.");
    }

    size_t zeroBits = 0;
    for (unsigned char byte : hash) {

        for (int i = 7; i >= 0; i--) {

            if ((byte >> i) & 1) {
                return false;
            }

            if (++zeroBits >= zeroBitsCount) {
                return true;
            }
        }


    }

    return false;
}


vector<unsigned char> solveRecursive(
        Hasher &hasher,
        size_t zeroBitsCount,
        vector<unsigned char> data,
        string &hash,
        size_t index = 0
)
{

    do {
        if (index >= data.size() - 1) {
            hash = hasher.computeHash(data);

            if (passes(hash, zeroBitsCount)) {
                return data;
            }
        } else {
            vector<unsigned char> result = solveRecursive(hasher, zeroBitsCount, data, hash, index + 1);
            if (!result.empty()) {
                return result;
            }
        }

        if (data[index] >= 0xFF) {
            break;
        }

        data[index]++;
    } while (true);

    return vector<unsigned char>();
}


int main(int argc, char *argv[])
{
    if (argc <= 1) {
        cout << "Too few arguments." << endl;
        return 4;
    }

    if (argc > 2) {
        cout << "Too many arguments." << endl;
        return 5;
    }
    size_t numberOfZeros;
    istringstream argStream(argv[1]);
    argStream >> numberOfZeros;

    if (!argStream.good() && !argStream.eof()) {
        cout << "Failed to parse argument." << endl;
        return 6;
    }

    vector<unsigned char> data;
    vector<unsigned char> result;
    Hasher hasher;

    string hash;
    do {
        data.push_back(0);

        try {
            result = solveRecursive(hasher, numberOfZeros, data, hash);
        } catch (const runtime_error &e) {
            cout << "Error: " << e.what() << endl;
            return 1;
        } catch (const invalid_argument &e) {
            cout << "Error: " << e.what() << endl;
            return 2;
        }

    } while (result.empty());

    cout << "Input:" << endl;
    printInput(result);

    cout << "Hash:" << endl;
    printHash(hash);

    return 0;
}
