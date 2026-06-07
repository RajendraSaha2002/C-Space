#include <iostream>
using namespace std;
int* createArray(int size)
{
    int* array = new int[size];
    for(int i =0; i<size; ++i)
    {
        array[i] = i*10;
    }
    return array;
}
int main()
{
    int* myArray = createArray(5);
    for(int i=0; i<5; ++i)
    {
        cout<<myArray[i]<<" ";
    }
    delete[] myArray;
    return 0;
}