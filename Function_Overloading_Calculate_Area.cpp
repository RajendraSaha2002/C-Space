#include <iostream>
#include <cmath>
using namespace std;

// Function to calculate area of a circle
double calculateArea(double radius) {
    return M_PI * radius * radius; // Area = π * r^2
}

// Function to calculate area of a rectangle
double calculateArea(double length, double breadth) {
    return length * breadth; // Area = length * breadth
}

// Function to calculate area of a triangle
double calculateArea(double base, double height, char shape) {
    // The third parameter 'shape' is just to differentiate from rectangle calculation
    // Area = 1/2 * base * height
    return 0.5 * base * height;
}

int main() {
    double radius, length, breadth, base, height;
    
    cout << "===== Area Calculator Program =====" << endl << endl;
    
    // Get circle radius from user
    cout << "Enter radius of circle: ";
    cin >> radius;
    cout << "Area of circle: " << calculateArea(radius) << " square units" << endl << endl;
    
    // Get rectangle dimensions from user
    cout << "Enter length of rectangle: ";
    cin >> length;
    cout << "Enter breadth of rectangle: ";
    cin >> breadth;
    cout << "Area of rectangle: " << calculateArea(length, breadth) << " square units" << endl << endl;
    
    // Get triangle dimensions from user
    cout << "Enter base of triangle: ";
    cin >> base;
    cout << "Enter height of triangle: ";
    cin >> height;
    cout << "Area of triangle: " << calculateArea(base, height, 't') << " square units" << endl;
    
    return 0;
}