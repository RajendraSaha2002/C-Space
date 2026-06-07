#include <iostream>
#include <sstream>
#include <string>
using namespace std;
int main()
{
    string s="Hey, I am at TP";
    stringstream object(s);
    string newstr;
    while(object>>newstr)
    {
        cout<<newstr<<" ";

    }
    return 0;
}

