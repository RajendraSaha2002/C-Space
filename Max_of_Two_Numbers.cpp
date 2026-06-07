#include <iostream>
using namespace std;

// Inline function to find maximum of two numbers
inline int findMax(int a, int b) {
    return (a > b) ? a : b;
}

int main() {
    int num1, num2;
    
    cout << "Enter two numbers: ";
    cin >> num1 >> num2;
    
    // Using the inline function to find maximum
    int max = findMax(num1, num2);
    
    cout << "Maximum of " << num1 << " and " << num2 << " is: " << max << endl;
    
    return 0;
}