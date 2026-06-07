#include <iostream>
using namespace std;
int main()
{
    int number=42;
    int* ptr=&number;
    cout<<"Original Value:"<<*ptr<<endl;
    *ptr=100;
    cout<<"Modified Value:"<<number<<endl;
    return 0;
}