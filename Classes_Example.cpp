#include <iostream>
using namespace std;
// Function to calculate the square of a number
class rectangle
{
    public:
    rectangle(int w, int h): width(w), height(h) {} // Constructor to initialize width and height
    int area() const // Method to calculate the area of the rectangle
    {
        return width * height; // Return the area of the rectangle
    }
    private:
    int width; // Width of the rectangle
    int height; // Height of the rectangle
};
rectangle createRectangle(int width, int height) {
    return rectangle(width, height); // Create and return a rectangle object}
}
int main() {
    rectangle rect = createRectangle(10, 5); // Create a rectangle with width=10 and height=20
    cout << "Area of given Rectangle is : " << rect.area() << endl; // Output the area of the rectangle
    return 0; // Indicate that the program ended successfully
}
