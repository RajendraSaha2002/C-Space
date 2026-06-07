#include <iostream>
using namespace std;

int main() {
    // Declare a constant value for Pi
    const double PI = 3.14159;

    // Display the constant value
    cout << "The value of PI is: " << PI << endl;

    // Attempting to modify PI will cause a compilation error
    // PI = 3.14; // Uncommenting this line will result in an error

    return 0;
}
