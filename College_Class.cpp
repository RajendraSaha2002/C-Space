#include <iostream>
#include <string>
using namespace std;

// College class definition
class college {
private:
    int collegeId;
    string name;
    string headOfDepartment;
    int numberOfCourses;

public:
    // Member function to accept details
    void acceptDetails() {
        cout << "Enter College ID: ";
        cin >> collegeId;
        
        cin.ignore(); // Clear input buffer
        
        cout << "Enter College Name: ";
        getline(cin, name);
        
        cout << "Enter Name of the Head of Department: ";
        getline(cin, headOfDepartment);
        
        cout << "Enter Number of Courses Offered: ";
        cin >> numberOfCourses;
    }
    
    // Member function to display details
    void displayDetails() {
        cout << "\n---- College Details ----" << endl;
        cout << "College ID: " << collegeId << endl;
        cout << "College Name: " << name << endl;
        cout << "Head of Department: " << headOfDepartment << endl;
        cout << "Number of Courses Offered: " << numberOfCourses << endl;
        cout << "------------------------" << endl;
    }
};

// Main function to demonstrate the college class
int main() {
    college myCollege;
    
    cout << "Enter College Information:" << endl;
    myCollege.acceptDetails();
    
    cout << "\nCollege Information:" << endl;
    myCollege.displayDetails();
    
    return 0;
}