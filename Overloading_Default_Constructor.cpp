#include <iostream>
using namespace std;
class MyClass
{
    private:
    int a, b;
    public:
    MyClass(): a(0), b(0) // Default constructor with member initializer list
    {
        cout << "Default constructor called" << endl;
    }
    MyClass(int x): a(x), b(0)
    {
        cout<<"Overloaded constructor (1 argument) called"<<endl;
    }
    MyClass(int x, int y): a(x), b(y)
    {
        cout<<"Overloaded constructor (2 arguments) called"<<endl;
    }
    void display()
    {
        cout << "a: " << a << ", b: " << b << endl;
    }
};
int main()
{
    MyClass obj1; // Calls default constructor
    obj1.display(); // Display values of a and b

    MyClass obj2(5); // Calls overloaded constructor with 1 argument
    obj2.display(); // Display values of a and b

    MyClass obj3(10, 20); // Calls overloaded constructor with 2 arguments
    obj3.display(); // Display values of a and b

    return 0; // Destructor will be called automatically here
}