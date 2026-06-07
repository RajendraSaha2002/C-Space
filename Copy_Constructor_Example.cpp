#include <iostream>
using namespace std;

class Example {
    int value;
public:
    Example(int v) {             // Parameterized constructor
        value = v;
        cout << "Value from parameterized constructor: " << value << endl;
    }
    Example(const Example &obj) { // Copy constructor
        value = obj.value;
        cout << "Value from copy constructor: " << value << endl;
    }
};

int main() {
    Example obj1(50);            // Calls parameterized constructor
    Example obj2 = obj1;         // Calls copy constructor
    return 0;
}