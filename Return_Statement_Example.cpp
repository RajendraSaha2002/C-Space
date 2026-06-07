#include <iostream>
using namespace std;
int sum(int a, int b) {
    return a + b; // This function returns the sum of two integers
}   
int main()
{
    int ans = sum(5, 2);
    cout<<"The sum of two integers 5 and 2 is: " << ans << endl; // Output the result
    return 0; // Indicate that the program ended successfully
}