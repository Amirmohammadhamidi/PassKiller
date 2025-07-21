#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "CPUCrackerEngine.hpp"

using namespace std;

int main()
{
    cout << "Usage example: <hash> <hash_type>" << endl;
    cout << "Supported types: md5, sha1, sha256, sha512" << endl;
    cout << "To exit the program, type: exit" << endl;

    CPUCracker cracker;
    string input;

    while (true)
    {
        cout << "\n>>> ";
        getline(cin, input);

        if (input == "exit")
            break;

        istringstream iss(input);
        string hash, type;
        vector<string> tokens;

        string token;
        while (iss >> token)
            tokens.push_back(token);

        if (tokens.size() != 2)
        {
            cout << "[!] Invalid input format. Use: <hash> <hash_type>" << endl;
            continue;
        }

        hash = tokens[0];
        type = tokens[1];

        cout << "[*] Cracking started..." << endl;
        string result = cracker.crack(hash, type, {});

        if (!result.empty())
        {
            cout << "[+] Password found: " << result << endl;
        }
        else
        {
            cout << "[-] Password not found." << endl;
        }
    }

    cout
        << "[*] Exiting..." << endl;
    return 0;
}
