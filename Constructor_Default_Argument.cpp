#include <iostream>
using namespace std;
void printMessage(string message ="I love you, Suchismita Saha")
{
    cout<<message<<endl;
}
int main()
{
    printMessage();
    printMessage("Hi, I am here !");
    return 0;
}