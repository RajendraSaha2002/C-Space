#include <iostream>
using namespace std;

int main() {
    // Declare variables for two numbers
    double num1, num2;

    // Ask the user to input two numbers
    cout << "Enter the first number: ";
    cin >> num1;

    cout << "Enter the second number: ";
    cin >> num2;

    // Perform addition
    double sum = num1 + num2;
    cout << "Sum: " << sum << endl;

    // Perform subtraction
    double difference = num1 - num2;
    cout << "Difference: " << difference << endl;

    // Perform multiplication
    double product = num1 * num2;
    cout << "Product: " << product << endl;

    // Perform division (check for division by zero)
    if (num2 != 0) {
        double quotient = num1 / num2;
        cout << "Quotient: " << quotient << endl;
    } else {
        cout << "Error: Division by zero is not allowed." << endl;
    }

    return 0;
}
