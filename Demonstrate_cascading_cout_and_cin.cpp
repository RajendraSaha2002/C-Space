#include <iostream>

int main() {
    int age;
    double height;
    std::string name;

    // Cascading std::cout
    std::cout << "Enter your name:" 
              << std::endl;
    std::cin >> name;  // Input name

    std::cout << "Enter your age:" 
              << std::endl;
    std::cin >> age;  // Input age

    std::cout << "Enter your height (in meters):" 
              << std::endl;
    std::cin >> height;  // Input height

    // Cascading std::cout
    std::cout << "\nThank you for providing your details! Here's the summary: " 
              << std::endl
              << "Name: " << name 
              << "\nAge: " << age 
              << "\nHeight: " << height << " meters." 
              << std::endl;

    return 0;
}
