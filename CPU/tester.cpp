#include <iostream>
#include "CPUCrackerEngine.hpp"
using namespace std;

int main()
{
    std::string input = "amir";

    std::cout << "Target MD5 hash: " << MD5::hash(input) << "\n";
    std::cout << "Target SHA1 hash: " << SHA1::hash(input) << "\n";
    std::cout << "Target SHA256 hash: " << SHA256::hash(input) << "\n";
    std::cout << "Target SHA512 hash: " << SHA512::hash(input) << "\n";

    // std::string targetHash = SHA512::hash(input); // hash of "abc"
    // CPUCracker cracker;
    // std::string result = cracker.crack(targetHash, "sha512", {});

    // if (!result.empty())
    // {
    //     std::cout << "[+] Password found: " << result << "\n";
    // }
    // else
    // {
    //     std::cout << "[-] Password not found.\n";
    // }

    return 0;
}