#include <iostream>
using namespace std;

class Student {
    int id;
    string name;
public:
    Student(int i, string n) {    // Parameterized constructor
        id = i;
        name = n;
    }
    void display() {
        cout << "ID: " << id << endl;
        cout << "Name: " << name << endl;
    }
};

int main() {
    int id;
    string name;

    cout << "Enter student ID: ";
    cin >> id;
    cout << "Enter student Name: ";
    cin >> name;

    Student s(id, name);
    s.display();

    return 0;
}