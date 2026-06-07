#include <iostream>
using namespace std;
class MyClass
{
    public:
    int a, b;
    // Default constructor
    MyClass(int x, int y)
    {
        a = x;
        b = y;
        cout << "Parameterized constructor called with values: " << a << ", " << b << endl;
    }
    void display()
    {
        cout << "a: " << a << ", b: " << b << endl;
    }
};
int main()
{
    // Creating an object of MyClass using the parameterized constructor
    MyClass obj(10, 20);
    obj.display(); // Displaying the values of a and b
    return 0;
}