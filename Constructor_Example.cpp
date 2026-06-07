#include <iostream>
using namespace std;
class Line
{
    public:
    void setLength(double len);
    double getLength(void);
    Line(); // Constructor declaration
    private:
    double length; // Length of a line
};
Line::Line(void)
{
    cout << "Object is being created" << endl;
}
void Line::setLength(double len)
{
    length = len;
}
double Line::getLength(void)
{
    return length;
}
int main(void)
{
    Line line; // Declare line as Line type object
    line.setLength(6.0); // Set length of line
    cout << "Length of line : " << line.getLength() << endl;
    return 0;
}
    