#include <iostream>
using namespace std;
void getInfo(string name, int age, double height)
{
    cout<<name<<"is"<<age<<"years old and"<<height<<"meters tall"<<endl;
}
int man()
{
    getInfo("Rajendra", 23, 1.78);
    getInfo("Suchismita", 21, 1.65);
    return 0;
}