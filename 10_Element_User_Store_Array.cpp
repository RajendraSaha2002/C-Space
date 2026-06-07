#include <iostream>

int main() {
    int arr[10];

    // Input 10 elements from user
    std::cout << "Enter 10 integers:" << std::endl;
    for(int i = 0; i < 10; ++i) {
        std::cin >> arr[i];
    }

    // Display the elements
    std::cout << "You entered: ";
    for(int i = 0; i < 10; ++i) {
        std::cout << arr[i] << " ";
    }
    std::cout << std::endl;

    return 0;
}