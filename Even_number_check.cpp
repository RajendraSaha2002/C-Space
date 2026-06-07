#include <iostream>
using namespace std;
int main()
{
    int num;
    cout<<"Enter the number to be checked:";
    cin>>num;
    if (num % 2==0)
    {
        cout<<num<<"is Even";
    }
    else
    {
        cout<<"is not Even";
    }
    return 0;
    
}