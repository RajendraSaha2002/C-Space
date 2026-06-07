#include <iostream>
using namespace std;
string func(int n)
{
    if(n%2) return "Given number is Odd!";
    else return "Given number is Even!";
}
int main()
{
    int a;
    cin>>a;
    cout<<func(a);
    return 0;
}