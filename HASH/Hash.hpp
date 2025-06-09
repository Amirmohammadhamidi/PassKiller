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
    char charSet[70];
    string passwordListPath;
    int length_lower_bound = 4;
    int length_upper_bound = 10;

public:
    Hash(string hash) { this->hash = hash; };

    std::vector<std::string> predict_Hash_type()
    {
        FileHandler fh;
        const vector<string> args = {hash};
        const string prediction_file_path = fh.get_project_path() + "/HASH/hash-id.py";
        string output = fh.runfile(prediction_file_path, args);
        istringstream stream(output);
        vector<string> tokens;
        std::string token;

        while (getline(stream, token))
        {
            tokens.push_back(token);
        }

        return tokens;
    }

    ~Hash();
    void set_type(char *type);
    void set_length_bounds(int length_lower_bound = 4, int length_upper_bound = 10);
    void loadcharSet(char charSet[]);
    void loadPasswordList(char *passwordListPath);
    void start_cracking();
    void finish_cracking();
};

#endif