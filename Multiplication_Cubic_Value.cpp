#include <iostream>
using namespace std;

// Inline function to calculate multiplication of two numbers
inline int multiply(int a, int b) {
    return a * b;
}

// Inline function to calculate cubic value
inline int cube(int a) {
    return a * a * a;
}

int main() {
    int num1, num2;
    
    cout << "Enter two numbers: ";
    cin >> num1 >> num2;
    
    // Calculate and display multiplication result
    cout << "Multiplication of " << num1 << " and " << num2 << " is: " 
         << multiply(num1, num2) << endl;
    
    // Calculate and display cubic values
    cout << "Cubic value of " << num1 << " is: " << cube(num1) << endl;
    cout << "Cubic value of " << num2 << " is: " << cube(num2) << endl;
    
    return 0;
}