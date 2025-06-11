#include <iostream>
#include "CPUCrackerEngine.hpp"
using namespace std;

int main()
{
    std::string input = "abc";
    std::string targetHash = MD5::hash(input); // hash of "abc"
    std::cout << "Target MD5 hash: " << targetHash << "\n";

    CPUCracker cracker;
    std::string result = cracker.crack(targetHash, "md5", {});

    if (!result.empty())
    {
        std::cout << "[+] Password found: " << result << "\n";
    }
    else
    {
        std::cout << "[-] Password not found.\n";
    }

    return 0;
}