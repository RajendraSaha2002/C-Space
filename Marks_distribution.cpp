#include <iostream>
using namespace std;

int main() {
    int marks;

    // Take marks input from the user
    cout << "Enter your marks: ";
    cin >> marks;

    // Display grade based on marks
    if (marks >= 70) {
        cout << "Grade: A" << endl;
    } else if (marks >= 60) {
        cout << "Grade: B" << endl;
    } else if (marks >= 50) {
        cout << "Grade: C" << endl;
    } else if (marks >= 40) {
        cout << "Grade: D" << endl;
    } else {
        cout << "Fail" << endl;
    }

    return 0;
}
