#include <iostream>
using namespace std;

class Example {
    int value;
public:
    Example() {      // Default constructor
        value = 100;
        cout << "Value from default constructor: " << value << endl;
    }
};

int main() {
    Example obj;     // Object creation calls default constructor
    return 0;
}