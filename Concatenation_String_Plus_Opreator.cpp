#include <iostream>
using namespace std;
int main()
{
    string initial_string("I love you Suchismita.");
    string new_string("I am here.");
    string a="Hey!!!" + initial_string;
    a+=new_string;
    a+="Could you help me ?";
    cout<<a<<endl;
    return 0;
} 
