#include <iostream>
#include <string>

// Define the Student class
class Student {
public:
    int id;
    std::string name;

    // Constructor to initialize id and name (optional, but good practice)
    Student(int studentId, std::string studentName) {
        id = studentId;
        name = studentName;
    }

    // Default constructor (if you want to create an object without initial values)
    Student() {
        id = 0; // or some default
        name = "N/A"; // or some default
    }

    // Function to display student information
    void displayStudent() {
        std::cout << "Student ID: " << id << std::endl;
        std::cout << "Student Name: " << name << std::endl;
    }
};

int main() {
    // Create an object of the Student class
    // Using the constructor with parameters
    Student student1(101, "Alice Smith"); 

    // Alternatively, you could create an object and then assign values:
    // Student student2;
    // student2.id = 102;
    // student2.name = "Bob Johnson";

    // Print the id and name values stored in the object
    std::cout << "Student Information:" << std::endl;
    student1.displayStudent();

    // If you used the second method for student2:
    // std::cout << "\nAnother Student Information:" << std::endl;
    // student2.displayStudent();

    return 0;
}