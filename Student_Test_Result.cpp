#include <iostream>
#include <string>
using namespace std;

// Class to store student roll number
class Students {
protected:
    int rollNumber;

public:
    Students() : rollNumber(0) {}
    
    void getRollNumber() {
        cout << "Enter Roll Number: ";
        cin >> rollNumber;
    }
    
    void showRollNumber() const {
        cout << "Roll Number: " << rollNumber << endl;
    }
};

// Class to store marks for two subjects
class Test {
protected:
    float subject1Marks;
    float subject2Marks;

public:
    Test() : subject1Marks(0), subject2Marks(0) {}
    
    void getMarks() {
        cout << "Enter marks for Subject 1: ";
        cin >> subject1Marks;
        cout << "Enter marks for Subject 2: ";
        cin >> subject2Marks;
    }
    
    void showMarks() const {
        cout << "Subject 1 Marks: " << subject1Marks << endl;
        cout << "Subject 2 Marks: " << subject2Marks << endl;
    }
};

// Result class inherits from both Students and Test classes
class Result : public Students, public Test {
private:
    float totalMarks;

public:
    Result() : totalMarks(0) {}
    
    void calculateTotal() {
        totalMarks = subject1Marks + subject2Marks;
    }
    
    void showResult() const {
        showRollNumber();  // From Students class
        showMarks();       // From Test class
        cout << "Total Marks: " << totalMarks << endl;
    }
};

int main() {
    cout << "=== Student Test Results System ===" << endl;
    
    Result student;
    
    // Get student details
    student.getRollNumber();  // From Students class
    student.getMarks();       // From Test class
    student.calculateTotal(); // Calculate total marks
    
    cout << "\n=== Student Result ===" << endl;
    student.showResult();     // Display all information
    
    return 0;
}