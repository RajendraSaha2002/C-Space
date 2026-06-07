#include <iostream>
using namespace std;
int getSquare(int num)
{
    return num * num; // This function returns the square of the input number
}
int main()
{
    int value =5;
    int result = getSquare(value);
    cout << "The square of " << value << " is: " << result << endl; // Output the result
    
    return 0; // Indicate that the program ended successfully
}

