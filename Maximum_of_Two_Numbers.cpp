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
    friend void findMax(Numbers n);
};

// Define the friend function
void findMax(Numbers n) {
    if (n.num1 > n.num2) {
        std::cout << "The maximum number is: " << n.num1 << std::endl;
    } else {
        std::cout << "The maximum number is: " << n.num2 << std::endl;
    }
}

int main() {
    Numbers n(25, 10);
    findMax(n);
    return 0;
}