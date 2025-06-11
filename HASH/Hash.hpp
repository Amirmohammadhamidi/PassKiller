#ifndef Hash_hpp
#define Hash_hpp

#include <iostream>
#include <sstream>
#include "../FileHandler.hpp"

using namespace std;
const string hash_identifier_path = "/HASH/hash-id.py";
class Hash
{
private:
    string hash;
    string type;
    const char *charset = {"abcdefghijklmnopqrstuvwxyz0123456789"};
    int length_lower_bound = 4;
    int length_upper_bound = 10;

public:
    Hash(string hash) { this->hash = hash; };
    const char *get_chartset() { return charset; };
    std::vector<std::string> predict_Hash_type();

    ~Hash();
};

#endif