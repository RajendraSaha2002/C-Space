#include <iostream>
using namespace std;
class Line
{
    public:
    int getLength(void);
    Line(int len); // Constructor declaration
    Line(const Line &obj); // Copy constructor declaration
    ~Line(); // Destructor declaration
    private:
    int *ptr; // Pointer to an int
};
Line::Line(int len) // Constructor definition
{
    cout << "Normal constructor allocating ptr." << endl;
    ptr = new int; // Allocate memory for the pointer
    *ptr = len; // Assign value to the allocated memory
}
Line::Line(const Line &obj) // Copy constructor definition
{
    cout << "Copy constructor allocating ptr." << endl;
    ptr = new int; // Allocate memory for the pointer
    *ptr = *(obj.ptr); // Copy the value from the object being copied
}
Line::~Line() // Destructor definition
{
    cout << "Freeing memory!" << endl;
    delete ptr; // Free the allocated memory
}
int Line::getLength(void) // Member function to get the length
{
    return *ptr; // Return the value pointed to by ptr
}
void display(Line obj) // Function to display the length of the line
{
    cout << "Length of line : " << obj.getLength() << endl; // Call getLength() to get the value
}
int main()
{
    Line line(10); // Create a Line object with length 10
    display(line); // Pass the object to the display function
    return 0; // Return success
}