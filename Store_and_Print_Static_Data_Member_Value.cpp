#include <iostream>

class MyClass {
public:
    // Declare a static data member
    static int count;

    MyClass() {
        // Increment the static counter each time an object is created
        count++;
    }
};

// Define and initialize the static data member outside the class
int MyClass::count = 0;

int main() {
    MyClass obj1; // count becomes 1
    MyClass obj2; // count becomes 2
    MyClass obj3; // count becomes 3

    // Access the static member directly using the class name
    std::cout << "The value of the static data member (count) is: " << MyClass::count << std::endl;

    return 0;
}