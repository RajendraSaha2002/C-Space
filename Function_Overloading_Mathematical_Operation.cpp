#include <iostream>
using namespace std;

// Function overloading with integer parameters
void calculate(int a, int b) {
    cout << "Operations with integers:" << endl;
    cout << "Addition: " << a << " + " << b << " = " << a + b << endl;
    cout << "Subtraction: " << a << " - " << b << " = " << a - b << endl;
    cout << "Multiplication: " << a << " * " << b << " = " << a * b << endl;
    
    if (b != 0) {
        cout << "Division: " << a << " / " << b << " = " << static_cast<float>(a) / b << endl;
    } else {
        cout << "Division: Cannot divide by zero" << endl;
    }
    cout << "------------------------" << endl;
}

// Function overloading with float parameters
void calculate(float a, float b) {
    cout << "Operations with floats:" << endl;
    cout << "Addition: " << a << " + " << b << " = " << a + b << endl;
    cout << "Subtraction: " << a << " - " << b << " = " << a - b << endl;
    cout << "Multiplication: " << a << " * " << b << " = " << a * b << endl;
    
    if (b != 0) {
        cout << "Division: " << a << " / " << b << " = " << a / b << endl;
    } else {
        cout << "Division: Cannot divide by zero" << endl;
    }
    cout << "------------------------" << endl;
}

// Function overloading with double parameters
void calculate(double a, double b) {
    cout << "Operations with doubles:" << endl;
    cout << "Addition: " << a << " + " << b << " = " << a + b << endl;
    cout << "Subtraction: " << a << " - " << b << " = " << a - b << endl;
    cout << "Multiplication: " << a << " * " << b << " = " << a * b << endl;
    
    if (b != 0) {
        cout << "Division: " << a << " / " << b << " = " << a / b << endl;
    } else {
        cout << "Division: Cannot divide by zero" << endl;
    }
    cout << "------------------------" << endl;
}

// Function overloading with mixed parameters (int and float)
void calculate(int a, float b) {
    cout << "Operations with mixed types (int, float):" << endl;
    cout << "Addition: " << a << " + " << b << " = " << a + b << endl;
    cout << "Subtraction: " << a << " - " << b << " = " << a - b << endl;
    cout << "Multiplication: " << a << " * " << b << " = " << a * b << endl;
    
    if (b != 0) {
        cout << "Division: " << a << " / " << b << " = " << a / b << endl;
    } else {
        cout << "Division: Cannot divide by zero" << endl;
    }
    cout << "------------------------" << endl;
}

int main() {
    // Testing the overloaded functions with different parameter types
    int num1 = 10, num2 = 5;
    float fnum1 = 15.5f, fnum2 = 3.5f;
    double dnum1 = 20.25, dnum2 = 4.75;
    
    cout << "Demonstrating function overloading with different parameter types:" << endl << endl;
    
    // Call with integer parameters
    calculate(num1, num2);
    
    // Call with float parameters
    calculate(fnum1, fnum2);
    
    // Call with double parameters
    calculate(dnum1, dnum2);
    
    // Call with mixed parameters
    calculate(num1, fnum2);
    
    return 0;
}