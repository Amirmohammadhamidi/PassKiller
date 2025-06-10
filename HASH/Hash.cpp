#include "Hash.hpp"
std::vector<std::string> Hash::predict_Hash_type()
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