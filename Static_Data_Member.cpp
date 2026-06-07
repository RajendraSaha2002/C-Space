#include <iostream>
#include <string>
using namespace std;
class Book
{
    private:
    string title;
    string author;
    public:
    static int totalBooks;
    Book(string bookTitle, string bookAuthor)
    {
        title =bookTitle;
        author =bookAuthor;
        totalBooks++;
    }
    static void printTotalBooks()
    {
        cout<<"Total number of books in the library:"<<totalBooks<<endl;
    }
    void displayBookInfo()
    {
        cout<<"Book Title:"<<title<<",Author:"<<author<<endl;
    }
};
int Book::totalBooks=0;
int main()
{
    Book book1("The Catcher in the Rye", "Suchismita Saha");
    Book book2("To kill a Mocking bird", "Parthib Saha");
    Book book3("1984", "Rajendra Saha");
    Book::printTotalBooks();
    book1.printTotalBooks();
    book2.printTotalBooks();
    book3.printTotalBooks();
    Book book4("Pride and Prejudice", "Sourav Saha");
    Book book5("The Great Gatsby", "Soumita Saha");
    Book::printTotalBooks();
    return 0;
    
}