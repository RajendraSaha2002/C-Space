#include <iostream>
using namespace std;
int factorial(int num)
{
    if(num<=1)
    {
        return 1;
    }
    else{
        return num*factorial(num-1);
    }
}
int main()
{
    int positive_number;
    cout<<"Enter a positive integer:";
    cin>>positive_number;
    if(positive_number<0)
    {
        cout<<"Wrong input, Factorial is not defined for negative integer"<<endl;
    }
    else{
        cout<<"Factorial of"<<positive_number<<"is"<<factorial(positive_number)<<endl;
    }
    return 0;
}