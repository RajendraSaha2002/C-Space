#include <iostream>

int main() {
    int rows, cols;

    // Get the size of the 2D array from the user
    std::cout << "Enter number of rows: ";
    std::cin >> rows;
    std::cout << "Enter number of columns: ";
    std::cin >> cols;

    int arr[100][100]; // Adjust size as needed

    // Input elements
    std::cout << "Enter elements:" << std::endl;
    for(int i = 0; i < rows; ++i) {
        for(int j = 0; j < cols; ++j) {
            std::cin >> arr[i][j];
        }
    }

    // Display elements
    std::cout << "The 2D array is:" << std::endl;
    for(int i = 0; i < rows; ++i) {
        for(int j = 0; j < cols; ++j) {
            std::cout << arr[i][j] << " ";
        }
        std::cout << std::endl;
    }

    return 0;
}