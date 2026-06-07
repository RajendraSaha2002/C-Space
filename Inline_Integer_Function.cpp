#include <iostream>
using namespace std;

// Inline function that returns an integer value
inline int getValue() {
    int value = 100; // You can change this or make it dynamic
    return value;
}

int main() {
    // Calling the inline function and getting integer value from it
    int result = getValue();
    
    cout << "Value returned from inline function: " << result << endl;
    
    return 0;
}