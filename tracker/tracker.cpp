// tracker.cpp
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <vector>
#include <map>
#include <sstream>
#include <string>
#include <fstream>
#include <set>
using namespace std;

#pragma comment(lib, "Ws2_32.lib")
#define PORT 8001  // Changed port to avoid conflicts
#define BUFLEN 1024

// Structure to store file information
struct FileInfo {
    string filename;
    string owner;
    string filepath;
    int size;
    set<string> groups; // Groups where this file is shared
};

// Group structure
struct Group {
    string groupId;
    string owner;
    set<string> members;
    set<string> pendingRequests;
    set<string> files; // Files shared in this group (filenames)
};

// Peer information
struct PeerInfo {
    string username;
    string ip;
    int port;
};

// Store users and their files
map<string, string> users; // username -> password
map<string, vector<FileInfo>> userFiles; // username -> files
map<SOCKET, string> loggedInUsers; // socket -> username
map<string, Group> groups; // groupId -> Group
map<string, map<string, bool>> downloads; // username -> {filename -> isComplete}
map<string, PeerInfo> peerInfo; // username -> PeerInfo
map<SOCKET, string> socketToIp; // socket -> IP address

// Parse command string into command and arguments
void parseCommand(const string& input, string& command, vector<string>& args) {
    stringstream ss(input);
    ss >> command;
    string arg;
    while (ss >> arg) {
        args.push_back(arg);
    }
}

// Send response to client
void sendResponse(SOCKET clientSock, const string& response) {
    send(clientSock, response.c_str(), response.length(), 0);
}

// Check if user is group owner
bool isGroupOwner(const string& username, const string& groupId) {
    if (groups.find(groupId) == groups.end()) return false;
    return groups[groupId].owner == username;
}

// Check if user is group member
bool isGroupMember(const string& username, const string& groupId) {
    if (groups.find(groupId) == groups.end()) return false;
    return groups[groupId].members.find(username) != groups[groupId].members.end();
}

// Find file owner by filename and group
string findFileOwner(const string& filename, const string& groupId) {
    for (const auto& userFile : userFiles) {
        for (const auto& file : userFile.second) {
            if (file.filename == filename && file.groups.find(groupId) != file.groups.end()) {
                return file.owner;
            }
        }
    }
    return "";
}

// Get file path for a specific user and file
string getFilePath(const string& username, const string& filename, const string& groupId) {
    for (const auto& file : userFiles[username]) {
        if (file.filename == filename && file.groups.find(groupId) != file.groups.end()) {
            std::cout << "Found file path: " << file.filepath << " for file: " << filename << std::endl;
            return file.filepath;
        }
    }
    std::cout << "File path not found for: " << filename << std::endl;
    return "";
}

// Structure to pass data to thread
struct ThreadData {
    SOCKET sock;
};

// Windows thread callback function
DWORD WINAPI clientHandlerThread(LPVOID lpParam) {
    ThreadData* data = static_cast<ThreadData*>(lpParam);
    SOCKET clientSock = data->sock;
    delete data; // Free the allocated memory
    
    // Get client IP address
    sockaddr_in clientAddr;
    int addrLen = sizeof(clientAddr);
    getpeername(clientSock, (sockaddr*)&clientAddr, &addrLen);
    char* ipBuffer = inet_ntoa(clientAddr.sin_addr);
    string clientIp(ipBuffer);
    socketToIp[clientSock] = clientIp;
    
    char buffer[BUFLEN];
    int recv_len;

    while ((recv_len = recv(clientSock, buffer, BUFLEN, 0)) > 0) {
        buffer[recv_len] = '\0';
        string input(buffer);
        std::cout << "Received from client: " << input << std::endl;

        string command;
        vector<string> args;
        parseCommand(input, command, args);
        string response;

        // Handle commands
        if (command == "create_user") {
            if (args.size() < 2) {
                response = "ERROR: Usage: create_user <username> <password>";
            } else {
                string username = args[0];
                string password = args[1];
                
                if (users.find(username) != users.end()) {
                    response = "ERROR: User already exists";
                } else {
                    users[username] = password;
                    response = "User created successfully";
                }
            }
        }
        else if (command == "login") {
            if (args.size() < 2) {
                response = "ERROR: Usage: login <username> <password>";
            } else {
                string username = args[0];
                string password = args[1];
                
                if (users.find(username) == users.end()) {
                    response = "ERROR: User does not exist";
                } else if (users[username] != password) {
                    response = "ERROR: Invalid password";
                } else {
                    loggedInUsers[clientSock] = username;
                    response = "Login successful";
                }
            }
        }
        else if (command == "register_peer") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 1) {
                response = "ERROR: Usage: register_peer <port>";
            } else {
                string username = loggedInUsers[clientSock];
                int port;
                
                try {
                    port = stoi(args[0]);
                    
                    // Register peer info
                    PeerInfo peer;
                    peer.username = username;
                    peer.ip = socketToIp[clientSock];
                    peer.port = port;
                    peerInfo[username] = peer;
                    
                    std::cout << "Registered peer " << username << " at " << peer.ip << ":" << port << std::endl;
                    response = "Peer registered successfully";
                }
                catch (const std::exception& e) {
                    response = "ERROR: Invalid port number";
                    std::cerr << "Error registering peer: " << e.what() << std::endl;
                }
            }
        }
        else if (command == "get_peer_info") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 2) {
                response = "ERROR: Usage: get_peer_info <group_id> <filename>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                string filename = args[1];
                
                std::cout << "Peer info request from " << username << " for file " << filename << " in group " << groupId << std::endl;
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (!isGroupMember(username, groupId)) {
                    response = "ERROR: Not a member of the group";
                } else {
                    // Find file owner
                    string fileOwner = findFileOwner(filename, groupId);
                    
                    if (fileOwner.empty()) {
                        response = "ERROR: File not found in group";
                    } else if (peerInfo.find(fileOwner) == peerInfo.end()) {
                        response = "ERROR: File owner not currently online";
                    } else {
                        // Return peer info (username IP:PORT)
                        PeerInfo peer = peerInfo[fileOwner];
                        response = peer.username + " " + peer.ip + ":" + to_string(peer.port);
                        std::cout << "Sending peer info: " << response << std::endl;
                    }
                }
            }
        }
        else if (command == "get_file_path") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 2) {
                response = "ERROR: Usage: get_file_path <group_id> <filename>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                string filename = args[1];
                
                string filePath = getFilePath(username, filename, groupId);
                if (filePath.empty()) {
                    response = "ERROR: File not found";
                } else {
                    response = filePath;
                }
            }
        }
        else if (command == "download_complete") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 2) {
                response = "ERROR: Usage: download_complete <group_id> <filename>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                string filename = args[1];
                
                // Mark download as complete
                downloads[username][filename] = true;
                response = "Download status updated";
            }
        }
        else if (command == "create_group") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 1) {
                response = "ERROR: Usage: create_group <group_id>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                
                if (groups.find(groupId) != groups.end()) {
                    response = "ERROR: Group already exists";
                } else {
                    Group newGroup;
                    newGroup.groupId = groupId;
                    newGroup.owner = username;
                    newGroup.members.insert(username); // Owner automatically joins
                    groups[groupId] = newGroup;
                    response = "Group created successfully";
                }
            }
        }
        else if (command == "join_group") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 1) {
                response = "ERROR: Usage: join_group <group_id>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (isGroupMember(username, groupId)) {
                    response = "ERROR: Already a member of the group";
                } else {
                    // Add to pending requests
                    groups[groupId].pendingRequests.insert(username);
                    response = "Join request sent";
                }
            }
        }
        else if (command == "leave_group") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 1) {
                response = "ERROR: Usage: leave_group <group_id>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (!isGroupMember(username, groupId)) {
                    response = "ERROR: Not a member of the group";
                } else if (isGroupOwner(username, groupId)) {
                    response = "ERROR: Group owner cannot leave the group";
                } else {
                    groups[groupId].members.erase(username);
                    response = "Left group successfully";
                }
            }
        }
        else if (command == "list_requests") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 1) {
                response = "ERROR: Usage: list_requests <group_id>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (!isGroupOwner(username, groupId)) {
                    response = "ERROR: Only group owner can list requests";
                } else {
                    response = "Pending requests for group " + groupId + ":\n";
                    for (const auto& requester : groups[groupId].pendingRequests) {
                        response += requester + "\n";
                    }
                    if (groups[groupId].pendingRequests.empty()) {
                        response += "No pending requests";
                    }
                }
            }
        }
        else if (command == "accept_request") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 2) {
                response = "ERROR: Usage: accept_request <group_id> <user_id>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                string targetUser = args[1];
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (!isGroupOwner(username, groupId)) {
                    response = "ERROR: Only group owner can accept requests";
                } else if (groups[groupId].pendingRequests.find(targetUser) == groups[groupId].pendingRequests.end()) {
                    response = "ERROR: No pending request from this user";
                } else {
                    groups[groupId].pendingRequests.erase(targetUser);
                    groups[groupId].members.insert(targetUser);
                    response = "User accepted to group";
                }
            }
        }
        else if (command == "list_groups") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else {
                response = "Available groups:\n";
                for (const auto& group : groups) {
                    response += group.first + " - Owner: " + group.second.owner + "\n";
                }
                if (groups.empty()) {
                    response += "No groups available";
                }
            }
        }
        else if (command == "list_files") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 1) {
                response = "ERROR: Usage: list_files <group_id>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (!isGroupMember(username, groupId)) {
                    response = "ERROR: Not a member of the group";
                } else {
                    response = "Files in group " + groupId + ":\n";
                    bool hasFiles = false;
                    
                    for (const auto& userFile : userFiles) {
                        for (const auto& file : userFile.second) {
                            if (file.groups.find(groupId) != file.groups.end()) {
                                response += file.filename + " (" + to_string(file.size) + " bytes) - Owner: " + file.owner + "\n";
                                hasFiles = true;
                            }
                        }
                    }
                    
                    if (!hasFiles) {
                        response += "No files in this group";
                    }
                }
            }
        }
        else if (command == "upload_file") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 2) {
                response = "ERROR: Usage: upload_file <file_path> <group_id>";
            } else {
                string username = loggedInUsers[clientSock];
                string filepath = args[0];
                string groupId = args[1];
                
                // Extract filename from path
                string filename = filepath.substr(filepath.find_last_of("/\\") + 1);
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (!isGroupMember(username, groupId)) {
                    response = "ERROR: Not a member of the group";
                } else {
                    // Check if file already registered for this user
                    bool fileExists = false;
                    for (auto& file : userFiles[username]) {
                        if (file.filename == filename) {
                            // Add group to existing file
                            file.groups.insert(groupId);
                            fileExists = true;
                            break;
                        }
                    }
                    
                    if (!fileExists) {
                        // Register new file
                        FileInfo fileInfo;
                        fileInfo.filename = filename;
                        fileInfo.owner = username;
                        fileInfo.filepath = filepath;
                        fileInfo.size = 1024; // Placeholder size
                        fileInfo.groups.insert(groupId);
                        userFiles[username].push_back(fileInfo);
                    }
                    
                    // Add file to group
                    groups[groupId].files.insert(filename);
                    response = "File uploaded successfully";
                }
            }
        }
        else if (command == "download_file") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 3) {
                response = "ERROR: Usage: download_file <group_id> <file_name> <destination_path>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                string filename = args[1];
                string destPath = args[2];
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (!isGroupMember(username, groupId)) {
                    response = "ERROR: Not a member of the group";
                } else {
                    // Check if file exists in group
                    bool fileFound = false;
                    string fileOwner;
                    
                    for (const auto& userFile : userFiles) {
                        for (const auto& file : userFile.second) {
                            if (file.filename == filename && file.groups.find(groupId) != file.groups.end()) {
                                fileFound = true;
                                fileOwner = file.owner;
                                break;
                            }
                        }
                        if (fileFound) break;
                    }
                    
                    if (!fileFound) {
                        response = "ERROR: File not found in group";
                    } else {
                        // Register download as in progress
                        downloads[username][filename] = false;
                        response = "Download request registered";
                    }
                }
            }
        }
        else if (command == "show_downloads") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else {
                string username = loggedInUsers[clientSock];
                
                if (downloads.find(username) == downloads.end() || downloads[username].empty()) {
                    response = "No downloads";
                } else {
                    response = "Downloads:\n";
                    for (const auto& download : downloads[username]) {
                        string status = download.second ? "[C]" : "[D]";
                        string filename = download.first;
                        
                        // Find which group this file belongs to
                        string groupId = "Unknown";
                        for (const auto& group : groups) {
                            if (group.second.files.find(filename) != group.second.files.end()) {
                                groupId = group.first;
                                break;
                            }
                        }
                        
                        response += status + " [" + groupId + "] " + filename + "\n";
                    }
                }
            }
        }
        else if (command == "stop_share") {
            if (loggedInUsers.find(clientSock) == loggedInUsers.end()) {
                response = "ERROR: Not logged in";
            } else if (args.size() < 2) {
                response = "ERROR: Usage: stop_share <group_id> <file_name>";
            } else {
                string username = loggedInUsers[clientSock];
                string groupId = args[0];
                string filename = args[1];
                
                if (groups.find(groupId) == groups.end()) {
                    response = "ERROR: Group does not exist";
                } else if (!isGroupMember(username, groupId)) {
                    response = "ERROR: Not a member of the group";
                } else {
                    bool fileFound = false;
                    
                    // Check if user owns this file
                    for (auto& file : userFiles[username]) {
                        if (file.filename == filename && file.groups.find(groupId) != file.groups.end()) {
                            // Remove group from file's groups
                            file.groups.erase(groupId);
                            fileFound = true;
                            
                            // Remove file from group if no more copies
                            bool stillShared = false;
                            for (const auto& userFile : userFiles) {
                                for (const auto& f : userFile.second) {
                                    if (f.filename == filename && f.groups.find(groupId) != f.groups.end()) {
                                        stillShared = true;
                                        break;
                                    }
                                }
                                if (stillShared) break;
                            }
                            
                            if (!stillShared) {
                                groups[groupId].files.erase(filename);
                            }
                            
                            break;
                        }
                    }
                    
                    if (fileFound) {
                        response = "File sharing stopped";
                    } else {
                        response = "ERROR: You don't own this file in this group";
                    }
                }
            }
        }
        else if (command == "logout") {
            if (loggedInUsers.find(clientSock) != loggedInUsers.end()) {
                string username = loggedInUsers[clientSock];
                
                // Remove peer info on logout
                if (peerInfo.find(username) != peerInfo.end()) {
                    peerInfo.erase(username);
                }
                
                loggedInUsers.erase(clientSock);
                response = "Logged out successfully";
            } else {
                response = "ERROR: Not logged in";
            }
        }
        else if (command == "quit" || command == "exit") {
            response = "Goodbye!";
            sendResponse(clientSock, response);
            break;
        }
        else {
            response = "ERROR: Unknown command";
        }

        // Send response
        sendResponse(clientSock, response);
    }

    if (loggedInUsers.find(clientSock) != loggedInUsers.end()) {
        string username = loggedInUsers[clientSock];
        
        // Remove peer info on disconnect
        if (peerInfo.find(username) != peerInfo.end()) {
            peerInfo.erase(username);
        }
        
        loggedInUsers.erase(clientSock);
    }
    
    if (socketToIp.find(clientSock) != socketToIp.end()) {
        socketToIp.erase(clientSock);
    }

    std::cout << "Client disconnected.\n";
    closesocket(clientSock);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: tracker <tracker_info.txt> <tracker_no>\n";
        return 1;
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed.\n";
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);  // Changed port to avoid conflicts
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSock, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed.\n";
        return 1;
    }

    listen(listenSock, SOMAXCONN);
    std::cout << "Tracker listening on port " << PORT << std::endl;
    std::cout << "Available commands: create_user, login, create_group, join_group, leave_group,\n";
    std::cout << "list_requests, accept_request, list_groups, list_files, upload_file, download_file,\n";
    std::cout << "show_downloads, stop_share, logout, quit\n";

    while (true) {
        SOCKET clientSock = accept(listenSock, NULL, NULL);
        if (clientSock == INVALID_SOCKET) continue;

        // Create thread data
        ThreadData* data = new ThreadData;
        data->sock = clientSock;
        
        // Create Windows thread
        HANDLE threadHandle = CreateThread(
            NULL,                   // Default security attributes
            0,                      // Default stack size
            clientHandlerThread,    // Thread function
            data,                   // Parameter to thread function
            0,                      // Run immediately
            NULL                    // Thread identifier (not used)
        );
        
        // Close handle (thread will run independently)
        if (threadHandle != NULL) {
            CloseHandle(threadHandle);
        }
    }

    closesocket(listenSock);
    WSACleanup();
    return 0;
}
