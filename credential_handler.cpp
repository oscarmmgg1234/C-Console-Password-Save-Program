#include "credential_interface.h"

//--------------------------------------------------------------------------------------
// User is unique
//--------------------------------------------------------------------------------------

bool PasswordFile::is_unique(string user, DataStructureType arg)
{
    if (DataStructureType::LINKEDLIST == arg)
    {
        for (auto it = credentials_list.begin(); it != credentials_list.end(); it++)
        {
            if (it->front() == user)
            {
                return false;
            }
        }
    }
    if (arg == DataStructureType::HASHMAP)
    {
        for (auto it = credentials.begin(); it != credentials.end(); it++)
        {
            if (it->first == user)
            {
                return false;
            }
        }
    }
    if (arg == DataStructureType::PARALLEL_VECTORS)
    {
        for (auto it = this->user.begin(); it != this->user.end(); it++)
        {
            if (*it == user)
            {
                return false;
            }
        }
    }
    if (arg == DataStructureType::VECTOR)
    {
        for (auto it = credential_vector.begin(); it != credential_vector.end(); it++)
        {
            if (*it == user)
            {
                return false;
            }
            it++;
        }
    }
    return true;
}

//--------------------------------------------------------------------------------------
// Constructor
//--------------------------------------------------------------------------------------

PasswordFile::PasswordFile(string filename, DataStructureType option, EncryptionType security)
{
    this->security = security;
    this->option = option;
    this->filename = filename;
    this->shouldUpdate = false;
    file_handler.open(filename.c_str(), ios::in);
    string u_temp, p_temp, pre_file_processing;
    file_handler >> pre_file_processing;
    if (pre_file_processing == "ENCRYPTED")
    {
        this->is_file_pre_encrypted = true;
    }
    else if (pre_file_processing == "UNENCRYPTED")
    {
        this->is_file_pre_encrypted = false;
    }
    else
    {

        throw runtime_error("Invalid File Format");
    }
    if (option == DataStructureType::VECTOR)
    {
        if (EncryptionType::NONE == security)
        {
            file_handler >> u_temp >> p_temp;
            while (!file_handler.eof())
            {
                if (this->is_file_pre_encrypted)
                {

                    if (this->is_unique(decrypt(u_temp), option))
                    {

                        credential_vector.push_back(decrypt(u_temp));
                        credential_vector.push_back(decrypt(p_temp));
                    }
                }
                else
                {
                    if (this->is_unique(u_temp, option))
                    {
                        credential_vector.push_back(u_temp);
                        credential_vector.push_back(p_temp);
                    }
                }
                file_handler >> u_temp >> p_temp;
            }
            file_handler.close();
            this->sync();
        }
        else
        {
            file_handler >> u_temp >> p_temp;
            while (!file_handler.eof())
            {

                if (this->is_unique(u_temp, option))
                {
                    if (this->is_file_pre_encrypted)
                    {
                        credential_vector.push_back(u_temp);
                        credential_vector.push_back(p_temp);
                    }
                    else
                    {
                        credential_vector.push_back(this->encrypt(u_temp));
                        credential_vector.push_back(this->encrypt(p_temp));
                    }
                }
                file_handler >> u_temp >> p_temp;
            }
            file_handler.close();
            this->is_file_pre_encrypted = true;
            this->sync();
        }
    }

    if (option == DataStructureType::LINKEDLIST)
    {
        if (EncryptionType::NONE == security)
        {
            file_handler >> u_temp >> p_temp;
            while (!file_handler.eof())
            {
                if (this->is_file_pre_encrypted)
                {
                    if (this->is_unique(this->decrypt(u_temp), option))
                    {
                        list<string> temp;
                        temp.push_back(this->decrypt(u_temp));
                        temp.push_back(this->decrypt(p_temp));
                        credentials_list.push_back(temp);
                    }
                }
                else
                {
                    if (this->is_unique(u_temp, option))
                    {
                        list<string> temp;
                        temp.push_back(u_temp);
                        temp.push_back(p_temp);
                        credentials_list.push_back(temp);
                    }
                }
                file_handler >> u_temp >> p_temp;
            }
            file_handler.close();

            this->sync();
        }
        else
        {
            file_handler >> u_temp >> p_temp;
            while (!file_handler.eof())
            {
                if (this->is_unique(u_temp, option))
                {
                    if (this->is_file_pre_encrypted)
                    {
                        list<string> temp;
                        temp.push_back(u_temp);
                        temp.push_back(p_temp);
                        credentials_list.push_back(temp);
                    }
                    else
                    {
                        list<string> temp;
                        temp.push_back(this->encrypt(u_temp));
                        temp.push_back(this->encrypt(p_temp));
                        credentials_list.push_back(temp);
                    }
                }
                file_handler >> u_temp >> p_temp;
            }
            file_handler.close();
            this->is_file_pre_encrypted = true;
            this->sync();
        }
    }
    if (option == DataStructureType::HASHMAP)
    {

        if (EncryptionType::ENCRYPT == security)
        {

            file_handler >> u_temp >> p_temp;
            while (!file_handler.eof())
            {

                if (this->is_unique(u_temp, option))
                {
                    if (this->is_file_pre_encrypted)
                    {
                        credentials.insert(std::pair<string, string>(u_temp, p_temp));
                    }
                    else
                    {
                        credentials.insert(std::pair<string, string>(encrypt(u_temp), encrypt(p_temp)));
                    }
                }
                file_handler >> u_temp >> p_temp;
            }
            file_handler.close();
            this->is_file_pre_encrypted = true;
            this->sync();
        }
        else
        {

            file_handler >> u_temp >> p_temp;
            while (!file_handler.eof())
            {
                if (this->is_file_pre_encrypted)
                {
                    if (this->is_unique(this->decrypt(u_temp), option))
                    {
                        credentials.insert(std::pair<string, string>(this->decrypt(u_temp), this->decrypt(p_temp)));
                    }
                }
                else
                {
                    if (this->is_unique(u_temp, option))
                    {
                        credentials.insert(std::pair<string, string>(u_temp, p_temp));
                    }
                }
                file_handler >> u_temp >> p_temp;
            }
            file_handler.close();

            this->sync();
        }
    }

    if (option == DataStructureType::PARALLEL_VECTORS)
    {

        if (EncryptionType::NONE == security)
        {
            file_handler >> u_temp >> p_temp;
            while (!file_handler.eof())
            {
                if (this->is_file_pre_encrypted)
                {
                    if (this->is_unique(this->decrypt(u_temp), option))
                    {
                        this->user.push_back(this->decrypt(u_temp));
                        this->password.push_back(this->decrypt(p_temp));
                    }
                }
                else
                {
                    if (this->is_unique(u_temp, option))
                    {
                        this->user.push_back(u_temp);
                        this->password.push_back(p_temp);
                    }
                }
                file_handler >> u_temp >> p_temp;
            }
            file_handler.close();
            this->sync();
        }
        else
        {

            file_handler >> u_temp >> p_temp;
            while (!file_handler.eof())
            {
                if (this->is_unique(u_temp, option))
                {
                    if (this->is_file_pre_encrypted)
                    {

                        user.push_back(u_temp);
                        password.push_back(p_temp);
                    }
                    else
                    {

                        user.push_back(encrypt(u_temp));
                        password.push_back(encrypt(p_temp));
                    }
                }
                file_handler >> u_temp >> p_temp;
            }
            file_handler.close();
            this->is_file_pre_encrypted = true;
            this->sync();
        }
    }
}

//--------------------------------------------------------------------------------------
// Destructor Method
//--------------------------------------------------------------------------------------

PasswordFile::~PasswordFile()
{
    file_handler.close();
}

//--------------------------------------------------------------------------------------
// Sync Method
//--------------------------------------------------------------------------------------

void PasswordFile::sync()
{
    file_handler.open(this->filename.c_str(), ios::out | ios::trunc);

    if (this->security == EncryptionType::ENCRYPT)
    {
        file_handler << "ENCRYPTED" << endl;
    }
    else
    {
        file_handler << "UNENCRYPTED" << endl;
    }

    if (DataStructureType::VECTOR == this->option)
    {
        for (auto it = credential_vector.begin(); it != credential_vector.end(); it++)
        {
            file_handler << *it << " ";
            it++;
            file_handler << *it << endl;
        }
        file_handler.close();
    }
    if (DataStructureType::HASHMAP == this->option)
    {
        for (auto it = credentials.begin(); it != credentials.end(); it++)
        {
            file_handler << it->first << " " << it->second << endl;
        }
        file_handler.close();
    }

    if (DataStructureType::PARALLEL_VECTORS == this->option)
    {
        for (size_t i = 0; i < user.size(); i++)
        {
            file_handler << user[i] << " " << password[i] << endl;
        }
        file_handler.close();
    }

    if (DataStructureType::LINKEDLIST == this->option)
    {
        for (const auto &entry : credentials_list)
        {
            file_handler << entry.front() << " " << entry.back() << endl;
        }
        file_handler.close();
    }
    this->shouldUpdate = false;
}

//--------------------------------------------------------------------------------------
// Encrypt
//--------------------------------------------------------------------------------------

string PasswordFile::encrypt(string s)
{
    for (int i = 0; i < s.size(); i++)
    {
        s[i] += salt;
    }
    return s;
}

//--------------------------------------------------------------------------------------
// Decrypt
//--------------------------------------------------------------------------------------

string PasswordFile::decrypt(string s)
{
    for (int i = 0; i < s.size(); i++)
    {
        s[i] -= salt;
    }
    return s;
}

//--------------------------------------------------------------------------------------
// Encryption Salt
//--------------------------------------------------------------------------------------

int PasswordFile::salt = 5;
void PasswordFile::newsalt(int ns)
{
    salt = ns;
}

//--------------------------------------------------------------------------------------
// Print Crendentials
//--------------------------------------------------------------------------------------

void PasswordFile::dump_crendentials()
{
    if (DataStructureType::LINKEDLIST == this->option)
    {
        for (auto it = credentials_list.begin(); it != credentials_list.end(); it++)
        {
            cout << it->front() << " " << it->back() << endl;
        }
    }
    if (DataStructureType::HASHMAP == this->option)
    {
        for (auto it = credentials.begin(); it != credentials.end(); it++)
        {
            cout << it->first << " " << it->second << endl;
        }
    }
    if (DataStructureType::PARALLEL_VECTORS == this->option)
    {
        for (int i = 0; i < user.size(); i++)
        {
            cout << user[i] << " " << password[i] << endl;
        }
    }
    if (DataStructureType::VECTOR == this->option)
    {
        for (auto it = credential_vector.begin(); it != credential_vector.end(); it++)
        {
            cout << *it << " ";
            it++;
            cout << *it << endl;
        }
    }
}

//--------------------------------------------------------------------------------------
// Add Credential Entry
//--------------------------------------------------------------------------------------

void PasswordFile::addpw(string newUser, string newPassword)
{

    if (security == EncryptionType::ENCRYPT)
    {
        newUser = encrypt(newUser);
        newPassword = encrypt(newPassword);
    }

    if (!is_unique(newUser, option))
    {
        return;
    }

    if (option == DataStructureType::VECTOR)
    {
        credential_vector.push_back(newUser);
        credential_vector.push_back(newPassword);
    }
    else if (option == DataStructureType::LINKEDLIST)
    {
        list<string> temp;
        temp.push_back(newUser);
        temp.push_back(newPassword);
        credentials_list.push_back(temp);
    }
    else if (option == DataStructureType::HASHMAP)
    {
        credentials[newUser] = newPassword;
    }
    else if (option == DataStructureType::PARALLEL_VECTORS)
    {
        user.push_back(newUser);
        password.push_back(newPassword);
    }
    this->shouldUpdate = true;
}

//--------------------------------------------------------------------------------------
// Check Credentials
//--------------------------------------------------------------------------------------

bool PasswordFile::checkpw(string user, string password)
{
    if (security == EncryptionType::ENCRYPT)
    {
        user = encrypt(user);
        password = encrypt(password);
    }

    if (option == DataStructureType::VECTOR)
    {
        for (size_t i = 0; i < credential_vector.size(); i += 2)
        {
            if (credential_vector[i] == user && credential_vector[i + 1] == password)
            {
                return true;
            }
        }
    }
    else if (option == DataStructureType::LINKEDLIST)
    {
        for (const auto &entry : credentials_list)
        {
            if (entry.front() == user && entry.back() == password)
            {
                return true;
            }
        }
    }
    else if (option == DataStructureType::HASHMAP)
    {
        if (credentials.find(user) != credentials.end() && credentials[user] == password)
        {
            return true;
        }
    }
    else if (option == DataStructureType::PARALLEL_VECTORS)
    {
        for (size_t i = 0; i < this->user.size(); i++)
        {
            if (this->user[i] == user && this->password[i] == password)
            {
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------------------
// Copy Constructor
//--------------------------------------------------------------------------------------

PasswordFile::PasswordFile(PasswordFile &copy)
{
    if (this != &copy)
    { // Check for self-assignment
        this->filename = copy.filename;
        this->security = copy.security;
        this->option = copy.option;

        if (option == DataStructureType::VECTOR)
        {
            this->credential_vector = copy.credential_vector;
        }
        else if (option == DataStructureType::LINKEDLIST)
        {
            this->credentials_list = copy.credentials_list;
        }
        else if (option == DataStructureType::HASHMAP)
        {
            this->credentials = copy.credentials;
        }
        else if (option == DataStructureType::PARALLEL_VECTORS)
        {
            this->user = copy.user;
            this->password = copy.password;
        }
    }
}

//--------------------------------------------------------------------------------------
// Copy Assignment Operator
//--------------------------------------------------------------------------------------

PasswordFile &PasswordFile::operator=(PasswordFile &copy)
{
    if (this != &copy)
    { // Check for self-assignment
        this->filename = copy.filename;
        this->security = copy.security;
        this->option = copy.option;

        if (option == DataStructureType::VECTOR)
        {
            this->credential_vector = copy.credential_vector;
        }
        else if (option == DataStructureType::LINKEDLIST)
        {
            this->credentials_list = copy.credentials_list;
        }
        else if (option == DataStructureType::HASHMAP)
        {
            this->credentials = copy.credentials;
        }
        else if (option == DataStructureType::PARALLEL_VECTORS)
        {
            this->user = copy.user;
            this->password = copy.password;
        }
    }
    return *this;
}

//--------------------------------------------------------------------------------------
// sync timer
//--------------------------------------------------------------------------------------

void PasswordFile::syncTimer()
{
    while (true)
    {
        if (this->shouldUpdate)
        {

            this->sync();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

//--------------------------------------------------------------------------------------
// start asyncronous sync
//--------------------------------------------------------------------------------------

void PasswordFile::sync_crendentials()
{
    std::thread(&PasswordFile::syncTimer, this).detach();
}
