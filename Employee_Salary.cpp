#include <iostream>
using namespace std;

class Employee {
public:
    string name;
    float salary;

    void getData() {
        cout << "Enter employee name: ";
        cin >> name;
        cout << "Enter salary: ";
        cin >> salary;
    }

    void display() {
        cout << "Employee Name: " << name << ", Salary: " << salary << endl;
    }
};

int main() {
    int n;
    cout << "Enter number of employees: ";
    cin >> n;
    Employee emp[n];

    for(int i = 0; i < n; i++) {
        cout << "\nEmployee " << i+1 << " details:" << endl;
        emp[i].getData();
    }

    cout << "\nEmployee Details:\n";
    for(int i = 0; i < n; i++) {
        emp[i].display();
    }

    return 0;
}