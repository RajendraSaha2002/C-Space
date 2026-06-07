#include <iostream>
using namespace std;
int main()
{
    string s="Hey, I am at TP.";
    for(int i=0;i<s.length();i++)
    {
        cout<<s[i]<<" ";

    }
    cout<<endl;
    for(char c:s)
    {
        cout<<c<<endl;

    }
    return 0;

}