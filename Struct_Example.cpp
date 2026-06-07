#include <iostream>
using namespace std;
struct point
{
    int x; // x-coordinate of the point
    int y; // y-coordinate of the point
};
point createPoint(int x, int y)
{
    point p;
    p.x = x; // Assigning x-coordinate
    p.y = y; // Assigning y-coordinate
    return p; // Returning the point structure

}
int main()
{
    point p =createPoint(10, 20); // Creating a point with x=10 and y=20
    cout << "Point coordinates: (" << p.x << ", " << p.y << ")" << endl; // Output the point coordinates
    return 0; // Indicate that the program ended successfully
}