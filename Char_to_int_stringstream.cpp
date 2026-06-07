#include <iostream>
#include <sstream>

int main() {
    char ch;
    std::cout << "Enter a single digit character: ";
    std::cin >> ch;
    
    if (!isdigit(ch)) {
        std::cout << "Invalid input! Please enter a digit (0-9)." << std::endl;
        return 1;
    }
    
    std::stringstream ss;
    ss << ch; // Insert character into stringstream
    int num;
    ss >> num; // Extract integer from stringstream
    
    std::cout << "The integer value is: " << num << std::endl;
    return 0;
}
