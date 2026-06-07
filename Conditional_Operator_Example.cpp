#include <iostream>
using namespace std;

int main() {
    int num1, num2;

    // Input two numbers from the user
    cout << "Enter first number: ";
    cin >> num1;
    cout << "Enter second number: ";
    cin >> num2;

    // Check which number is larger using conditional operator
    cout << "The larger number is: " 
         << (num1 > num2 ? num1 : num2) << endl;

    // Check if the first number is even or odd using the conditional operator
    cout << "The first number is " 
         << (num1 % 2 == 0 ? "even" : "odd") << endl;

    // Check if the second number is even or odd using the conditional operator
    cout << "The second number is " 
         << (num2 % 2 == 0 ? "even" : "odd") << endl;

    return 0;
}
