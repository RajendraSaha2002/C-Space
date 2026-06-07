#include <iostream>
using namespace std;
int main()
{
    int x=5;
    int y=10;
    auto my_lambda=[=, &x]()->int
    {
        cout<<"Inside lambda:"<<endl;
        x +=10;
        cout<<"Captured 'x' by reference inside lambda:"<<x<<endl;
        int sum=y+5;
        cout<<"Captured 'y' by value inside lambda:"<<y<<endl;
        cout<<"Sum of 'y' & 5 inside lambda:"<<sum<<endl;
        return sum;
    };
    int result=my_lambda();
    cout<<"Value of 'x' outside lambda after modification:"<<x<<endl;
    cout<<"Value of 'y' outside lambda(no modification):"<<y<<endl;
    return 0;
}