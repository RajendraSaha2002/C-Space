#include <iostream>
#include <string>

class Student {
public:
    int id;
    std::string name;
    static std::string collegeName;

    // Constructor to initialize student details
    Student(int i, std::string n) {
        id = i;
        name = n;
    }

    void display() {
        std::cout << "ID: " << id << ", Name: " << name << ", College: " << collegeName << std::endl;
    }
};

// Define the static data member
std::string Student::collegeName = "ABC College of Technology";

int main() {
    Student s1(101, "Alice");
    Student s2(102, "Bob");

    s1.display();
    s2.display();

    // Change the static college name, which affects all students
    Student::collegeName = "XYZ University";

    std::cout << "\nAfter changing the college name:" << std::endl;
    s1.display();
    s2.display();

    return 0;
}