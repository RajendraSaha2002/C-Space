#include <iostream>
using namespace std;

class Interest {
    float principal, year, rate, simple_interest;
public:
    Interest(int p, int y, int r) {         // Constructor with int rate
        principal = p;
        year = y;
        rate = r;
        simple_interest = (principal * year * rate) / 100;
    }
    Interest(int p, int y, float r) {       // Constructor with float rate
        principal = p;
        year = y;
        rate = r;
        simple_interest = (principal * year * rate) / 100;
    }
    void display() {
        cout << "Principal: " << principal << endl;
        cout << "Year: " << year << endl;
        cout << "Rate: " << rate << endl;
        cout << "Simple Interest: " << simple_interest << endl;
    }
};

int main() {
    int p, y, r;
    float rf;

    cout << "Enter principal: ";
    cin >> p;
    cout << "Enter year: ";
    cin >> y;
    cout << "Enter integer rate: ";
    cin >> r;

    Interest obj1(p, y, r);
    obj1.display();

    cout << "\nEnter float rate: ";
    cin >> rf;

    Interest obj2(p, y, rf);
    obj2.display();

    return 0;
}