#include <iostream>
using namespace std;
int main()
{
    int a=20;
    int *p=&a;
    cout<<"Address of variable a:"<<p<<endl;
    cout<<"Value of variable a:"<<*p<<endl;
    return 0;
}