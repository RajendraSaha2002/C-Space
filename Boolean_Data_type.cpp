#include <iostream>
using namespace std;
int main()
{
    bool flag;
    flag=1;
    bool flag1=true;
    cout<<flag<<""<<flag1<<endl;
    int count=0;
    while(flag)
    {
        count++;
        if(count>=3) flag=false;
    }
    cout<<count<<""<<flag<<endl;
    if(flag1)cout<<"True flag1"<<endl;
    else cout<<"False flag1"<<endl;
    return 0;
}