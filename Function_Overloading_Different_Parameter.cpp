#include <iostream>
using namespace std;
void show(int a)
{
    cout<<"Integer value:"<<a<<std::endl;
}
void show(double a)
{
    cout<<"Double value:"<<a<<std::endl;
}
int main()
{
    show(10);
    show(3.14);
    return 0;
}