#include <iostream>
#include <string>

class Student {
public:
    std::string name;
    int age;

    void display() {
        std::cout << "Name: " << name << ", Age: " << age << std::endl;
    }
};

int main() {
    int num_students;
    std::cout << "Enter the number of students: ";
    std::cin >> num_students;

    // Dynamically allocate an array of Student objects
    Student* students = new Student[num_students] {
        {"Alice", 20}, {"Bob", 22}, {"Charlie", 19}
    };

    std::cout << "\nStudent Information:" << std::endl;
    for (int i = 0; i < num_students; ++i) {
        students[i].display();
    }

    // Deallocate the dynamically allocated memory
    delete[] students;
    students = nullptr;

    std::cout << "\nMemory for student data deallocated successfully." << std::endl;

    return 0;
}