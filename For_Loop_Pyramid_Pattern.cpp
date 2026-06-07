#include <iostream>
using namespace std;

int main() {
    int rows = 5; // Number of rows in the pyramid

    // Outer loop for each row
    for (int i = 1; i <= rows; i++) {
        // Inner loop to print the numbers for each row
        for (int j = 1; j <= i; j++) {
            cout << i; // Print the row number
        }
        cout << endl; // Move to the next line after each row
    }

    return 0;
}
