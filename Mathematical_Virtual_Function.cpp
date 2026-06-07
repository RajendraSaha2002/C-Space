#include <iostream>

// Base class
class Shape {
public:
    // Virtual function to calculate the area.
    // `= 0` makes it a pure virtual function, making Shape an abstract class.
    virtual double area() const = 0;

    // Virtual function to display the shape's name and details.
    virtual void display() const = 0;

    // Virtual destructor to ensure proper memory cleanup.
    virtual ~Shape() {
        std::cout << "Shape destructor called." << std::endl;
    }
};

// ---
// Derived class for Circle
class Circle : public Shape {
private:
    double radius;

public:
    Circle(double r) : radius(r) {}

    // Overridden area() function for Circle.
    double area() const override {
        return 3.14159 * radius * radius;
    }

    // Overridden display() function for Circle.
    void display() const override {
        std::cout << "Shape: Circle" << std::endl;
        std::cout << "Radius: " << radius << std::endl;
        std::cout << "Area: " << area() << std::endl;
    }
};

// ---
// Derived class for Rectangle
class Rectangle : public Shape {
private:
    double length;
    double width;

public:
    Rectangle(double l, double w) : length(l), width(w) {}

    // Overridden area() function for Rectangle.
    double area() const override {
        return length * width;
    }

    // Overridden display() function for Rectangle.
    void display() const override {
        std::cout << "Shape: Rectangle" << std::endl;
        std::cout << "Length: " << length << std::endl;
        std::cout << "Width: " << width << std::endl;
        std::cout << "Area: " << area() << std::endl;
    }
};

// ---
// Derived class for Trapezoid
class Trapezoid : public Shape {
private:
    double base1;
    double base2;
    double height;

public:
    Trapezoid(double b1, double b2, double h) : base1(b1), base2(b2), height(h) {}

    // Overridden area() function for Trapezoid.
    double area() const override {
        return 0.5 * (base1 + base2) * height;
    }

    // Overridden display() function for Trapezoid.
    void display() const override {
        std::cout << "Shape: Trapezoid" << std::endl;
        std::cout << "Base 1: " << base1 << std::endl;
        std::cout << "Base 2: " << base2 << std::endl;
        std::cout << "Height: " << height << std::endl;
        std::cout << "Area: " << area() << std::endl;
    }
};

// ---
// Main function to demonstrate the program
int main() {
    // Using base class pointers to create objects of derived classes
    Shape* myCircle = new Circle(5.0);
    Shape* myRectangle = new Rectangle(4.0, 6.0);
    Shape* myTrapezoid = new Trapezoid(3.0, 5.0, 4.0);

    std::cout << "--- Displaying Circle ---" << std::endl;
    myCircle->display();
    std::cout << std::endl;

    std::cout << "--- Displaying Rectangle ---" << std::endl;
    myRectangle->display();
    std::cout << std::endl;

    std::cout << "--- Displaying Trapezoid ---" << std::endl;
    myTrapezoid->display();
    std::cout << std::endl;

    // Deleting objects using base class pointers.
    // The virtual destructors will ensure the correct destructors are called.
    delete myCircle;
    delete myRectangle;
    delete myTrapezoid;

    return 0;
}