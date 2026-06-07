#include <iostream>
using namespace std;

// First function with 2 parameters
void calculate(int a, int b) {
    int sum = a + b;
    int product = a * b;
    cout << "Function with 2 parameters:" << endl;
    cout << "Sum: " << sum << endl;
    cout << "Multiplication: " << product << endl;
    cout << "------------------------" << endl;
}

// Second function with 3 parameters (overloaded)
void calculate(int a, int b, int c) {
    int sum = a + b + c;
    int product = a * b * c;
    cout << "Function with 3 parameters:" << endl;
    cout << "Sum: " << sum << endl;
    cout << "Multiplication: " << product << endl;
    cout << "------------------------" << endl;
}

int main() {
    // Call the function with 2 parameters
    calculate(5, 10);
    
    // Call the function with 3 parameters
    calculate(5, 10, 15);
    
    return 0;
}