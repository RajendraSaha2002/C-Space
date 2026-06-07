#include <iostream>

int main() {
    // Dynamically allocate memory for a single integer
    int* single_int = new int;
    *single_int = 10;
    std::cout << "Value of the dynamically allocated integer: " << *single_int << std::endl;

    // Deallocate the memory
    delete single_int;
    single_int = nullptr; // Good practice to prevent a dangling pointer

    std::cout << "\nMemory deallocated for the single integer." << std::endl;

    // --- Array allocation ---

    // Dynamically allocate memory for an array of 5 integers
    int* array_of_ints = new int[5];

    // Initialize the array elements
    for (int i = 0; i < 5; ++i) {
        array_of_ints[i] = (i + 1) * 10;
    }

    // Print the elements of the dynamically allocated array
    std::cout << "\nValues of the dynamically allocated array:" << std::endl;
    for (int i = 0; i < 5; ++i) {
        std::cout << "Element " << i << ": " << array_of_ints[i] << std::endl;
    }

    // Deallocate the memory for the array
    delete[] array_of_ints;
    array_of_ints = nullptr; // Good practice

    std::cout << "\nMemory deallocated for the array." << std::endl;

    return 0;
}