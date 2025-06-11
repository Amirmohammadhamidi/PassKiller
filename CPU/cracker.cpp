#include <iostream>
#include <vector>
#include "HashCrackerEngine.hpp" // Make sure this declares MD5CPUCracker
using namespace std;

int main()
{
    MD5CPUCracker cracker;

    // The second argument must be a vector<string>, even if it's unused
    vector<string> unusedInput;

    string result = cracker.crack("63eefbd45d89e8c91f24b609f7539942", unusedInput);

    if (!result.empty())
    {
        cout << "Password found: " << result << endl;
    }
    else
    {
        cout << "Password not found." << endl;
    }

    return 0;
}
