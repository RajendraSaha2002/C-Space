#include <iostream>
using namespace std;

int main() {
    int num1, num2, sum;

    // Prompt the user to enter the first integer
    cout << "Enter the first integer: ";
    cin >> num1;

    // Prompt the user to enter the second integer
    cout << "Enter the second integer: ";
    cin >> num2;

    // Calculate the sum of the two numbers
    sum = num1 + num2;

    // Display the result
    cout << "The sum of " << num1 << " and " << num2 << " is " << sum << "." << endl;

    return 0;
}
