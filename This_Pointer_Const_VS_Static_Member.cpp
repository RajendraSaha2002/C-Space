#include <iostream>
class MyClass {
public:
	int data;
	MyClass(int val): data(val) {}
    // Static member function
    void printData() const {
        std::cout << "Data: " << data << std::endl;
    }
    static void showMessage() {
        std::cout << "This is a static member function !" << std::endl;
    }
    private:
    // Static member variable
    static int staticData;
};
// Definition of static member variable
int main()
{

    

    MyClass obj(10);
    obj.printData(); // Calls non-static member function
    MyClass::showMessage(); // Calls static member function

    return 0;
}