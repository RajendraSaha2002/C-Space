#include <iostream>
using namespace std;

int main() {
    int choice;

    // Display menu
    cout << "Welcome to the Call Center!" << endl;
    cout << "Please select your preferred language:" << endl;
    cout << "1. English" << endl;
    cout << "2. Hindi" << endl;
    cout << "3. Gujarati" << endl;
    cout << "Enter the number corresponding to your language choice: ";
    cin >> choice;

    // Switch-case statement to handle language selection
    switch (choice) {
        case 1:
            cout << "You have selected English." << endl;
            break;
        case 2:
            cout << "You have selected Hindi." << endl;
            break;
        case 3:
            cout << "You have selected Gujarati." << endl;
            break;
        default:
            cout << "Invalid choice! Please enter a number between 1 and 3." << endl;
    }

    return 0;
}
