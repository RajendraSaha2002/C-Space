#include <iostream>
using namespace std;
int globalValue =100;
int& getGlobalValue()
{
    return globalValue;
}
int main()
{
    int& ref = getGlobalValue();
    ref =200;
    cout<<"Global Value:"<<globalValue<<endl;
    return 0;
}