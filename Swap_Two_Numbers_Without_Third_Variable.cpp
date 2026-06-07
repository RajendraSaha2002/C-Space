#include <iostream>

class Numbers {
private:
    int num1;
    int num2;

public:
    Numbers(int a, int b) {
        num1 = a;
        num2 = b;
    }

    // Declare the friend function
    friend void swapNumbers(Numbers &n);

    void display() {
        std::cout << "Num1: " << num1 << ", Num2: " << num2 << std::endl;
    }
};

// Define the friend function
void swapNumbers(Numbers &n) {
    n.num1 = n.num1 + n.num2;
    n.num2 = n.num1 - n.num2;
    n.num1 = n.num1 - n.num2;
}

int main() {
    Numbers n(5, 8);

    std::cout << "Before swap:" << std::endl;
    n.display();

    swapNumbers(n);

    std::cout << "After swap:" << std::endl;
    n.display();

    return 0;
}