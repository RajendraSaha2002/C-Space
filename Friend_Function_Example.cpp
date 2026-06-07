#include <iostream>
using namespace std;
class Box
{
    double width;
public:
friend void printWidth(Box box);
void setWidth(double wid);
    
};
void Box::setWidth(double wid) {
    width = wid;
}
void printWidth(Box box) {
    cout << "Width of box: " << box.width << endl;
}
int main() {
    Box box;
    box.setWidth(10.5);
    printWidth(box); // Accessing private member through friend function
    return 0;
}