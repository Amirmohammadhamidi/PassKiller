#include <iostream>
#include "Hash.hpp"
using namespace std;
int main()
{
    Hash *hash = new Hash("99754106633f94d350db34d548d6091a");
    cout << hash->predict_Hash_type()[0] << endl;
}