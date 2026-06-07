#include <bits/stdc++.h>
using namespace std;
int main()
{
    int *ptr;
    cout<<*ptr<<endl;
    int a=11;
    ptr=&a;
    cout<<*ptr<<endl<<ptr<<endl;
    *ptr=10;
    cout<<*ptr<<endl<<ptr;
    return 0;
}