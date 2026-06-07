#include <iostream>
using namespace std;
class MyClass
{
    private:
    int value;
    public:
    MyClass(int v) : value(v) {} // Constructor to initialize value
    MyClass(const MyClass &obj) : value(obj.value) // Copy constructor
    {
        cout<<"Explicit copy constructor called."<<endl;
    }
   void display() const // Function to display the value
    {
        cout << "Value: " << value << endl;
    }
};
void processObject(MyClass obj)
{
    cout << "Processing object in function." << endl;
    obj.display(); // Display the value of the object
}
int main()
{
    MyClass obj1(10);
    MyClass obj2 = obj1; // Calls the copy constructor
    obj1.display(); // Display value of obj1
    obj2.display(); // Display value of obj2
    processObject(obj1); // Pass obj1 to the function, which will invoke the copy constructor
    return 0; // Return success
}