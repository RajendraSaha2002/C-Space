#include <iostream>

// Base class (abstract)
class Shape {
public:
    // Pure virtual function. This makes Shape an abstract class.
    virtual double area() const = 0;
    
    // Virtual function that can be overridden.
    virtual void display() const {
        std::cout << "This is a generic shape." << std::endl;
    }

    // Virtual destructor for proper memory cleanup.
    virtual ~Shape() {}
};

// ---
// Derived class: Circle
class Circle : public Shape {
private:
    double radius;

public:
    Circle(double r) : radius(r) {}

    // Override the pure virtual function to calculate the area of a circle.
    double area() const override {
        return 3.14159 * radius * radius;
    }
    
    // Override the display function.
    void display() const override {
        std::cout << "Shape: Circle" << std::endl;
        std::cout << "Radius: " << radius << std::endl;
        std::cout << "Area: " << area() << std::endl;
    }
};

// ---
// Derived class: Rectangle
class Rectangle : public Shape {
private:
    double length;
    double width;

public:
    Rectangle(double l, double w) : length(l), width(w) {}

    // Override the pure virtual function to calculate the area of a rectangle.
    double area() const override {
        return length * width;
    }
    
    // Override the display function.
    void display() const override {
        std::cout << "Shape: Rectangle" << std::endl;
        std::cout << "Length: " << length << std::endl;
        std::cout << "Width: " << width << std::endl;
        std::cout << "Area: " << area() << std::endl;
    }
};

// ---
// Derived class: Trapezoid
class Trapezoid : public Shape {
private:
    double base1, base2, height;

public:
    Trapezoid(double b1, double b2, double h) : base1(b1), base2(b2), height(h) {}

    // Override the pure virtual function to calculate the area of a trapezoid.
    double area() const override {
        return 0.5 * (base1 + base2) * height;
    }

    // Override the display function.
    void display() const override {
        std::cout << "Shape: Trapezoid" << std::endl;
        std::cout << "Base 1: " << base1 << std::endl;
        std::cout << "Base 2: " << base2 << std::endl;
        std::cout << "Height: " << height << std::endl;
        std::cout << "Area: " << area() << std::endl;
    }
};

// ---
// Main function to demonstrate polymorphism
int main() {
    // Array of base class pointers
    const int numShapes = 3;
    Shape* shapes[numShapes];

    // Populate the array with objects of different derived classes
    shapes[0] = new Circle(5.0);
    shapes[1] = new Rectangle(4.0, 6.0);
    shapes[2] = new Trapezoid(3.0, 5.0, 4.0);

    // Loop through the array and call functions polymorphically
    std::cout << "--- Calculating Areas ---" << std::endl;
    for (int i = 0; i < numShapes; ++i) {
        shapes[i]->display();
        std::cout << std::endl;
    }

    // Clean up dynamically allocated memory
    for (int i = 0; i < numShapes; ++i) {
        delete shapes[i];
    }

    return 0;
}