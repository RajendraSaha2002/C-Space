#include <iostream>
using namespace std;
enum RGB
{
    Red,
    Green,
    Blue,
};
void printColor(RGB color)
{
    switch(color)
    {
        case Red: cout<<"Color is Red";
        break;
        case Green:cout<<"Color is Green";
        break;
        case Blue:cout<<"Color is Blue";
        break;
    }
}
int main()
{
    RGB myColor=Red;
    int value=myColor;
    cout<<"Integer value:"<<value<<endl;
    printColor(myColor);
    return 0;
}
    