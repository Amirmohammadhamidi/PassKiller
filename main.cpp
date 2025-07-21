#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include "HashCrackerEngine.hpp"

using namespace std;

int main()
{
    HashCrackerManager manager;

    cout << "GPU Craker" << endl;
    cout << "Usage example: <hash> <hash_type>" << endl;
    cout << "Supported types: md5, sha1, sha256" << endl;
    cout << "To exit the program, type: exit" << endl;

    while (true)
    {
        cout << "\n>>> ";

        string input;
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

        type += "_bruteforce";

        auto start = std::chrono::high_resolution_clock::now();
        std::string cracked = manager.crackHash(hash, {}, type, "gpu");
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end - start;
        if (cracked.empty())
            std::cout << "Password not found!" << std::endl;
        else
            std::cout << "Cracked password: " << cracked << std::endl;
        std::cout << "Time taken: " << elapsed.count() << " seconds" << std::endl;
    }

    return 0;
}