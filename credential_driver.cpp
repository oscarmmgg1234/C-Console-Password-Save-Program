#include "credential_interface.h"
#include <chrono>
#define timespec chrono::high_resolution_clock::now();

PasswordFile &constructor_test(DataStructureType type, EncryptionType option); // test prototypes
void addpw_test(PasswordFile &credential_handler, size_t start, size_t end);

//--------------------------------------------------------------------------------------
// driver
//--------------------------------------------------------------------------------------

int main()
{

    auto test = constructor_test(DataStructureType::PARALLEL_VECTORS, EncryptionType::NONE);
    test.sync_crendentials();
    addpw_test(test, 0, 1);
    cout << test.checkpw("testUsername0", "testPassword0");
    string input;
    while (true)
    {
        std::cout << "Enter a username and password separated by a space (or 'exit' to quit): ";
        getline(std::cin, input);

        if (input == "exit")
        {
            break; // Exit the loop if the user enters 'exit'
        }
        if (input == "verify")
        {
            cout << "Enter a username and password separated by a space to verify (or 'exit' to quit): ";
            getline(std::cin, input);
            size_t spacePos = input.find(' ');
            if (spacePos != std::string::npos)
            {
                std::string username = input.substr(0, spacePos);
                std::string password = input.substr(spacePos + 1);
                bool status = test.checkpw(username, password);
                cout << "The password is question is " << (status ? "valid" : "invalid") << endl;
            }
            }
        else{
        // Split the input into username and password
        size_t spacePos = input.find(' ');
        if (spacePos != std::string::npos)
        {
            std::string username = input.substr(0, spacePos);
            std::string password = input.substr(spacePos + 1);

            test.addpw(username, password);
            // Process username and password here
            std::cout << "Username: " << username << ", Password: " << password << std::endl;
        }
        else
        {
            std::cout << "Invalid input. Please enter a username and password separated by a space." << std::endl;
        }
    }
    }

    return 0;
}

//--------------------------------------------------------------------------------------
// constructor test
//--------------------------------------------------------------------------------------

PasswordFile &constructor_test(DataStructureType type, EncryptionType option)
{
    auto start = timespec;
    PasswordFile *credential_handler = new PasswordFile("credentials.txt", type, option);
    auto stop = timespec;
    auto duration = chrono::duration_cast<chrono::milliseconds>(stop - start).count();
    cout << "Constructor Test" << endl;
    cout << endl;
    cout << "execution duration: " << duration << "ms" << endl;
    cout << endl;
    if (credential_handler->checkpw("oscar", "oscar_pass"))
    {
        cout << "check_password function status: password match" << endl;
    }
    return *credential_handler;
}

//--------------------------------------------------------------------------------------
// addpw test
//--------------------------------------------------------------------------------------

void addpw_test(PasswordFile &credential_handler, size_t start_index, size_t end_index)
{
    auto start = timespec;
    for (int i = start_index; i < end_index; i++)
    {
        string username = "testUsername" + to_string(i);
        string password = "testPassword" + to_string(i);
        credential_handler.addpw(username, password);
    }
    auto stop = timespec;
    auto duration = chrono::duration_cast<chrono::milliseconds>(stop - start).count();
    cout << "Addpw Test" << endl;
    cout << endl;
    cout << "execution duration: " << duration << "ms" << endl;
    cout << endl;
}
