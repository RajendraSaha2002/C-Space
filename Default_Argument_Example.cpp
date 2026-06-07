#include <iostream>
using namespace std;
int main()
{
    double price, discount = 12.0;
    cout<<"Enter the price of the item:";
    cin>>price;
    double total =price -(price* discount/100);
    cout<<"The total price after a"<<discount<<"% discount is:"<<total<<endl;
    return 0;
}