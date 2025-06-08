#ifndef Hash_hpp
#define Hash_hpp

#include <iostream>
#include <string>
#include <vector>

using namespace std;

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
    Hash(string hash)
    {
        this->hash = hash;
    };

    std::vector<std::string> predict_type(string hash)
    {
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