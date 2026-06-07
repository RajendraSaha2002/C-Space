#include <iostream>
using namespace std;
class ClassName {
    private:
        int privateData;
    protected:
        int protectedData;
    public:
    ClassName():        privateData(0), protectedData(0) {}
    friend void
    friendFunction(ClassName &obj);
};
void friendFunction(ClassName &obj) {
    // Accessing private and protected members of ClassName
    obj.privateData = 10;
    obj.protectedData = 20;
    cout << "Private Data: " << obj.privateData << endl;
    cout << "Protected Data: " << obj.protectedData << endl;
}
int main() {
    ClassName obj;
    friendFunction(obj); // Calling the friend function
    return 0;
}