#include <string>
#include <iostream>
class Student
{
    public:
    Student(const std::string& name, int age, double grade):name(name), age(age), grade(grade){}
    Student(const std::string& name, int age):Student(name , age, 0.0){}
    Student(const std::string& name):Student(name, 18, 0.0){}
    void display() const{
        std::cout<<"Name:"<<name<<", Age:"<<age<<", Grade:"<<grade<<"\n";
    }
    private:
    std::string name;
    int age;
    double grade;
};
int main()
{
    Student s1("Suchismita", 22, 90.5);
    Student s2("Rajendra", 23);
    Student s3("Parthib", 25);
    s1.display();
    s2.display();
    s3.display();
    return 0;
}