#include <iostream>
using namespace std;

int main() {
    int age;

    // Ask for user's age
    cout << "Enter your age: ";
    cin >> age;

    // Print the entered age
    cout << "Your age is: " << age << endl;

    // Check voting eligibility
    if (age >= 18) {
        cout << "You are eligible to vote!" << endl;
    } else {
        cout << "You are not eligible to vote." << endl;
    }

    return 0;
}
