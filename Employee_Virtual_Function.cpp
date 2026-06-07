#include <iostream>
#include <string>

// ---
// Step 1: Base class at the top of the diamond
class Person {
public:
    std::string name;
    int id;

    // A simple function to display person's info.
    void display_person_info() const {
        std::cout << "Name: " << name << std::endl;
        std::cout << "ID: " << id << std::endl;
    }
};

// ---
// Step 2: Intermediate derived classes inheriting virtually from Person
class Employee : virtual public Person {
public:
    std::string company;
    double salary;
};

class Student : virtual public Person {
public:
    std::string college;
    double gpa;
};

// ---
// Step 3: Final class inheriting from both intermediate classes
// This class will have only one shared copy of the Person base class.
class Manager : public Employee, public Student {
public:
    std::string department;
};

// ---
// Main function to demonstrate the program
int main() {
    // Create an object of the Manager class
    Manager my_manager;

    // Now, we can access the Person members directly from the Manager object.
    // There is no ambiguity because there is only one shared 'Person' part.
    my_manager.name = "John Doe";
    my_manager.id = 101;

    // Set members specific to Employee and Student
    my_manager.company = "Tech Corp";
    my_manager.salary = 85000.00;
    my_manager.college = "State University";
    my_manager.gpa = 3.8;

    // Set members specific to Manager
    my_manager.department = "Sales";

    // Call the function from the 'Person' base class.
    // The compiler knows exactly which 'Person' to use.
    std::cout << "--- Manager Information ---" << std::endl;
    my_manager.display_person_info();
    
    std::cout << "Company: " << my_manager.company << std::endl;
    std::cout << "Salary: $" << my_manager.salary << std::endl;
    std::cout << "College: " << my_manager.college << std::endl;
    std::cout << "GPA: " << my_manager.gpa << std::endl;
    std::cout << "Department: " << my_manager.department << std::endl;

    return 0;
}