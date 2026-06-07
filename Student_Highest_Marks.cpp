#include <iostream>
using namespace std;

class Student {
public:
    string name;
    int marks;

    void getData() {
        cout << "Enter student name: ";
        cin >> name;
        cout << "Enter marks: ";
        cin >> marks;
    }
};

int main() {
    int n, maxIndex = 0;
    cout << "Enter number of students: ";
    cin >> n;
    Student stu[n];

    for(int i = 0; i < n; i++) {
        cout << "\nStudent " << i+1 << " details:" << endl;
        stu[i].getData();
    }

    for(int i = 1; i < n; i++) {
        if(stu[i].marks > stu[maxIndex].marks) {
            maxIndex = i;
        }
    }

    cout << "\nStudent with highest marks:\n";
    cout << "Name: " << stu[maxIndex].name << ", Marks: " << stu[maxIndex].marks << endl;

    return 0;
}