#include <iostream>

// Function template to swap two values
template <typename T>
void swapValues(T& a, T& b) {
    T temp = a;
    a = b;
    b = temp;
}

int main() {
    // Example with integers
    int num1 = 10, num2 = 20;
    std::cout << "Before swap: num1 = " << num1 << ", num2 = " << num2 << std::endl;
    swapValues(num1, num2);
    std::cout << "After swap: num1 = " << num1 << ", num2 = " << num2 << std::endl;

    std::cout << std::endl;

    // Example with floating-point numbers
    double float1 = 5.5, float2 = 10.1;
    std::cout << "Before swap: float1 = " << float1 << ", float2 = " << float2 << std::endl;
    swapValues(float1, float2);
    std::cout << "After swap: float1 = " << float1 << ", float2 = " << float2 << std::endl;

    return 0;
}