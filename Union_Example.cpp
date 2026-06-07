#include <iostream>
#include <cstring>
using namespace std;
union Data
{
    int intValue;
    float floatValue;
    char strValue[50];

};
int main()
{
    Data data;
    data.intValue=2002;
    cout<<"TutorialPoint: Founded in:"<<data.intValue<<endl;
    data.floatValue=5.95;
    cout<<"My Float value is:"<<data.floatValue<<endl;
    strcpy(data.strValue, "Hello TutorialPoint Learner");
    cout<<data.strValue<<endl;
    cout<<"Integer after string assignment:"<<data.intValue<<endl;
    return 0;
}