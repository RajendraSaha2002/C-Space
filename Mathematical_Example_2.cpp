#include <iostream>
using namespace std;

int main() {
    double num1, num2;

    // Input two numbers from the user
    cout << "Enter the first number: ";
    cin >> num1;

    cout << "Enter the second number: ";
    cin >> num2;

    // Addition using the assignment operator
    num1 += num2;  // num1 = num1 + num2
    cout << "After addition, num1 is: " << num1 << endl;

    // Subtraction using the assignment operator
    num1 -= num2;  // num1 = num1 - num2
    cout << "After subtraction, num1 is: " << num1 << endl;

    // Multiplication using the assignment operator
    num1 *= num2;  // num1 = num1 * num2
    cout << "After multiplication, num1 is: " << num1 << endl;

    // Division using the assignment operator (check for division by zero)
    if (num2 != 0) {
        num1 /= num2;  // num1 = num1 / num2
        cout << "After division, num1 is: " << num1 << endl;
    } else {
        cout << "Error: Division by zero is not allowed." << endl;
    }

    return 0;
}
