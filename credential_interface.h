#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include <unordered_map>
#include <list>
#include <stack>
#include <thread>

#ifndef CREDENTIALS_INTERFACE_H
#define CRENDENTIALS_INTERFACE_H

using namespace std;

enum class DataStructureType
{
    PARALLEL_VECTORS,
    HASHMAP,
    LINKEDLIST,
    VECTOR
};

enum class EncryptionType
{
    NONE,
    ENCRYPT
};

class PasswordFile
{
public:
    PasswordFile(string filename, DataStructureType option, EncryptionType security); // opens the file and reads the names/passwords in the vectors user and password.
    PasswordFile(PasswordFile &copy);                                                 // copy constructor
    PasswordFile &operator=(PasswordFile &copy);                                      // copy assignment operator
    ~PasswordFile();                                                                  // destructor closes file
    void addpw(string newuser, string newpassword);                                   // this adds a new user/password to the vectors and writes the vectors to the file filename
    bool checkpw(string user, string passwd);                                         // returns true if user exists and password matches
    static void newsalt(int ns);
    void dump_crendentials();
    void sync_crendentials();  
    int deletepw(string user);                                                       //starts a thread to periodically update the credentials 
private:
    bool shouldUpdate;
    void syncTimer();
    list<list<string> > credentials_list;
    static int salt;
    vector<string> credential_vector;
    EncryptionType security; // class variable to determine if the credentials are encrypted
    DataStructureType option;
    unordered_map<string, string> credentials; // the list of usernames/passwords using an alternative data structure
    fstream file_handler;                      // the file handler
    string filename;
    bool is_file_pre_encrypted; // the file that contains password information
    vector<string> user;        // the list of usernames
    vector<string> password;    // the list of passwords
    void sync();
    string encrypt(string s);
    string decrypt(string s);
    bool is_unique(string user, DataStructureType args);
};

#endif