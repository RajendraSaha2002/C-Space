#include <iostream>
using namespace std;
void even(int n);
void odd(int n);
void even(int n)
{
    if(n==0)
    {
        cout<<"Even"<<endl;
    }
    else{
        odd(n-1);
    }
}
void odd(int n)
{
    if(n==0)
    {
        cout<<"odd"<<endl;

    }
    else{
        even(n-1);
    }
}
int main()
{
    even(4);
    odd(5);
    return 0;
}