#include <iostream>
#include <vector>
#include <string>

// Function template to sort an array using bubble sort
template <typename T>
void sortArray(T arr[], int size) {
    for (int i = 0; i < size - 1; ++i) {
        for (int j = 0; j < size - i - 1; ++j) {
            if (arr[j] > arr[j + 1]) {
                // Swap elements
                T temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

// Function to display array elements
template <typename T>
void printArray(T arr[], int size) {
    for (int i = 0; i < size; ++i) {
        std::cout << arr[i] << " ";
    }
    std::cout << std::endl;
}

int main() {
    // Example with integer array
    int intArray[] = {5, 2, 9, 1, 5};
    int intArraySize = sizeof(intArray) / sizeof(intArray[0]);
    std::cout << "Original integer array: ";
    printArray(intArray, intArraySize);

    sortArray(intArray, intArraySize);
    std::cout << "Sorted integer array: ";
    printArray(intArray, intArraySize);

    std::cout << std::endl;

    // Example with double array
    double doubleArray[] = {3.3, 1.1, 8.8, 6.6, 4.4};
    int doubleArraySize = sizeof(doubleArray) / sizeof(doubleArray[0]);
    std::cout << "Original double array: ";
    printArray(doubleArray, doubleArraySize);

    sortArray(doubleArray, doubleArraySize);
    std::cout << "Sorted double array: ";
    printArray(doubleArray, doubleArraySize);

    return 0;
}