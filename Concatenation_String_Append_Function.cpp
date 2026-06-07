#include <iostream>
using namespace std;
int main()
{
    string initial_string("I love you Suchismita.");
    string new_string("I am here.");
    initial_string.append(new_string);
    initial_string.append("Could you help me ?");
    cout<<initial_string<<endl;
    return 0;

}