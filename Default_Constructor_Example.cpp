#include <iostream>
using namespace std;
class DemoDC
{
    private:
    int num1, num2;
    public:
    DemoDC(); // Default constructor declaration
    void display();
};

DemoDC::DemoDC()
{
    num1 = 10;
    num2 = 20;
}

void DemoDC::display()
{
    cout << "num1: " << num1 << ", num2: " << num2 << endl;
}
int main()
{
    DemoDC obj; // Default constructor is called here
    obj.display(); // Display the values of num1 and num2
    return 0; // Destructor will be called automatically here
}