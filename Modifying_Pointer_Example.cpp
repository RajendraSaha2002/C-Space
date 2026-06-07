#include <iostream>
using namespace std;
int main()
{
    int var1=10;
    int var2=20;
    int* ptr=&var1;
    cout<<"Value pointed by ptr:"<<*ptr<<endl;
    ptr =&var2;
    cout<<"Value pointed by ptr, after modification:"<<*ptr<<endl;
    int* dynamicPtr =new int(30);
    ptr =dynamicPtr;
    cout<<"Value pointed by ptr after dynamic allocation:"<<*ptr<<endl;
    delete dynamicPtr;
    return 0;
}
