// client.cpp
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <fstream>
#include <thread>
#include <algorithm> // For std::min

#pragma comment(lib, "Ws2_32.lib")
#define BUFLEN 1024
#define FILE_CHUNK_SIZE 8192

SOCKET trackerSock;
bool loggedIn = false;
std::string currentUser;
int clientPort = 9000; // Default port for listening to peer connections
bool serverRunning = false;
HANDLE serverThreadHandle = NULL;
CRITICAL_SECTION downloadLock; // Windows synchronization mechanism

// File transfer tracking
struct DownloadInfo {
    std::string filename;
    std::string groupId;
    std::string sourcePeer;
    bool isCompleted;
    int totalSize;
    int downloadedSize;
};

std::map<std::string, DownloadInfo> downloads;

// Peer info
struct PeerInfo {
    std::string username;
    std::string ip;
    int port;
};

// Forward declarations of functions
void displayHelp();
void showDownloads();
std::string sendToTrackerAndGetResponse(const std::string &message);
void sendToTracker(const std::string &message);
bool sendFile(const std::string& filePath, SOCKET peerSock);
bool receiveFile(const std::string& savePath, SOCKET peerSock, const std::string& filename, const std::string& groupId);
void downloadFile(const std::string& groupId, const std::string& filename, const std::string& savePath);
DWORD WINAPI handleClient(LPVOID lpParam);
DWORD WINAPI peerServerFunc(LPVOID lpParam);
void startPeerServer();
void stopPeerServer();

// Custom string duplication function
char* duplicateString(const char* str) {
    size_t len = strlen(str) + 1;
    char* dup = new char[len];
    strcpy(dup, str);
    return dup;
}

// Thread function for downloads
struct DownloadParams {
    char* groupId;
    char* filename;
    char* savePath;
};

DWORD WINAPI downloadThreadFunc(LPVOID lpParam) {
    DownloadParams* params = (DownloadParams*)lpParam;
    downloadFile(params->groupId, params->filename, params->savePath);
    
    // Free allocated memory
    delete[] params->groupId;
    delete[] params->filename;
    delete[] params->savePath;
    delete params;
    
    return 0;
}

// Send message to tracker and get response
std::string sendToTrackerAndGetResponse(const std::string &message) {
    send(trackerSock, message.c_str(), message.length(), 0);
    char buffer[BUFLEN];
    int recv_len = recv(trackerSock, buffer, BUFLEN, 0);
    if (recv_len > 0) {
        buffer[recv_len] = '\0';
        return std::string(buffer);
    }
    return "";
}

void sendToTracker(const std::string &message) {
    std::string response = sendToTrackerAndGetResponse(message);
    
    // Update login status if needed
    if (message.find("login") == 0 && response == "Login successful") {
        // Extract username from login command
        std::istringstream iss(message);
        std::string cmd, username;
        iss >> cmd >> username;
        currentUser = username;
        loggedIn = true;
        
        // Auto-register peer after successful login
        std::string registerCmd = "register_peer " + std::to_string(clientPort);
        std::string regResponse = sendToTrackerAndGetResponse(registerCmd);
        std::cout << "Peer registration: " << regResponse << std::endl;
    } else if (message == "logout" && response == "Logged out successfully") {
        loggedIn = false;
        currentUser = "";
    }
    
    std::cout << "Tracker: " << response << std::endl;
}

// File transfer functions
bool sendFile(const std::string& filePath, SOCKET peerSock) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filePath << std::endl;
        // Try current directory as fallback
        std::string filename = filePath.substr(filePath.find_last_of("/\\") + 1);
        file.open(filename, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Could not open file" << std::endl;
            return false;
        }
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    int fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Send file size first
    std::string sizeMsg = std::to_string(fileSize);
    send(peerSock, sizeMsg.c_str(), sizeMsg.length(), 0);
    
    // Wait for acknowledgment
    char ackBuffer[BUFLEN];
    recv(peerSock, ackBuffer, BUFLEN, 0);
    
    // Send file data in chunks
    char buffer[FILE_CHUNK_SIZE];
    int totalSent = 0;
    int progress = 0;
    
    while (!file.eof()) {
        file.read(buffer, FILE_CHUNK_SIZE);
        int bytesRead = file.gcount();
        
        if (bytesRead > 0) {
            int bytesSent = send(peerSock, buffer, bytesRead, 0);
            if (bytesSent <= 0) {
                std::cerr << "Error sending file data" << std::endl;
                file.close();
                return false;
            }
            
            totalSent += bytesSent;
            
            // Display progress
            int newProgress = (totalSent * 100) / fileSize;
            if (newProgress >= progress + 10) {  // Update every 10%
                progress = newProgress;
                std::cout << "Upload progress: " << progress << "%" << std::endl;
            }
        }
    }
    
    file.close();
    std::cout << "Upload complete" << std::endl;
    return true;
}

bool receiveFile(const std::string& savePath, SOCKET peerSock, const std::string& filename, const std::string& groupId) {
    try {
        // Receive file size
        char sizeBuffer[BUFLEN];
        int recv_len = recv(peerSock, sizeBuffer, BUFLEN, 0);
        if (recv_len <= 0) {
            std::cerr << "Error receiving file size" << std::endl;
            return false;
        }
        
        sizeBuffer[recv_len] = '\0';
        
        // Try to parse file size with error handling
        int fileSize = 0;
        try {
            fileSize = std::stoi(sizeBuffer);
        } catch (const std::exception& e) {
            std::cerr << "Error parsing file size" << std::endl;
            return false;
        }
        
        // Send acknowledgment
        send(peerSock, "ACK", 3, 0);
        
        // Open file for writing
        std::ofstream fileStream(savePath, std::ios::binary);
        if (!fileStream) {
            std::cerr << "Error creating file: " << savePath << std::endl;
            return false;
        }
        
        // Receive file in chunks
        char buffer[FILE_CHUNK_SIZE];
        int totalReceived = 0;
        int progress = 0;
        
        // Update download info
        downloads[filename].totalSize = fileSize;
        
        while (totalReceived < fileSize) {
            int bytesToReceive = std::min(FILE_CHUNK_SIZE, fileSize - totalReceived);
            int bytesRead = recv(peerSock, buffer, bytesToReceive, 0);
            
            if (bytesRead <= 0) {
                std::cerr << "Error receiving file data" << std::endl;
                fileStream.close();
                return false;
            }
            
            fileStream.write(buffer, bytesRead);
            totalReceived += bytesRead;
            
            // Update download info
            downloads[filename].downloadedSize = totalReceived;
            
            // Display progress
            int newProgress = (totalReceived * 100) / fileSize;
            if (newProgress >= progress + 10) {  // Update every 10%
                progress = newProgress;
                std::cout << "Download progress: " << progress << "%" << std::endl;
            }
        }
        
        fileStream.close();
        
        // Mark download as complete
        downloads[filename].isCompleted = true;
        
        std::cout << "Download complete" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error receiving file" << std::endl;
        return false;
    }
}

// Function to download a file from a peer
void downloadFile(const std::string& groupId, const std::string& filename, const std::string& savePath) {
    try {
        // Get peer info from tracker
        std::string peerInfoCmd = "get_peer_info " + groupId + " " + filename;
        std::string response = sendToTrackerAndGetResponse(peerInfoCmd);
        
        if (response.find("ERROR") == 0) {
            std::cerr << response << std::endl;
            return;
        }
        
        // Parse response to get peer info (format: username IP:PORT)
        std::istringstream iss(response);
        std::string username, ipPort;
        iss >> username >> ipPort;
        
        size_t colonPos = ipPort.find(':');
        if (colonPos == std::string::npos) {
            std::cerr << "Invalid peer address format" << std::endl;
            return;
        }
        
        std::string peerIp = ipPort.substr(0, colonPos);
        std::string portStr = ipPort.substr(colonPos + 1);
        
        // Clean the port string to ensure only digits
        std::string cleanPortStr;
        for (char c : portStr) {
            if (isdigit(c)) {
                cleanPortStr += c;
            }
        }
        
        // Add error handling for port conversion
        int peerPort;
        try {
            if (cleanPortStr.empty()) {
                std::cerr << "Error: Port string is empty after cleaning" << std::endl;
                return;
            }
            peerPort = std::stoi(cleanPortStr);
        } catch (const std::exception& e) {
            std::cerr << "Error parsing port number: " << e.what() << std::endl;
            return;
        }
        
        std::cout << "Connecting to peer for file " << filename << "..." << std::endl;
        
        // Connect to peer
        SOCKET peerSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (peerSock == INVALID_SOCKET) {
            std::cerr << "Socket creation failed" << std::endl;
            return;
        }
        
        sockaddr_in peerAddr;
        memset(&peerAddr, 0, sizeof(peerAddr));  // Zero initialize
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(peerPort);
        peerAddr.sin_addr.s_addr = inet_addr(peerIp.c_str());
        
        if (peerAddr.sin_addr.s_addr == INADDR_NONE) {
            std::cerr << "Invalid IP address format" << std::endl;
            closesocket(peerSock);
            return;
        }
        
        if (connect(peerSock, (sockaddr*)&peerAddr, sizeof(peerAddr)) == SOCKET_ERROR) {
            std::cerr << "Connection to peer failed" << std::endl;
            closesocket(peerSock);
            return;
        }
        
        // Initialize download info
        DownloadInfo info;
        info.filename = filename;
        info.groupId = groupId;
        info.sourcePeer = username;
        info.isCompleted = false;
        info.totalSize = 0;
        info.downloadedSize = 0;
        downloads[filename] = info;
        
        // Request file
        std::string requestCmd = "REQUEST_FILE " + groupId + " " + filename;
        send(peerSock, requestCmd.c_str(), requestCmd.length(), 0);
        
        // Receive file
        if (receiveFile(savePath, peerSock, filename, groupId)) {
            std::cout << "File downloaded successfully to " << savePath << std::endl;
        } else {
            std::cout << "Error downloading file" << std::endl;
        }
        
        closesocket(peerSock);
    } catch (const std::exception& e) {
        std::cerr << "Error in download process: " << e.what() << std::endl;
    }
}

// Function to handle client connections for file requests
DWORD WINAPI handleClient(LPVOID lpParam) {
    SOCKET clientSock = *(SOCKET*)lpParam;
    delete (SOCKET*)lpParam;
    
    char buffer[BUFLEN];
    int recv_len = recv(clientSock, buffer, BUFLEN, 0);
    buffer[recv_len] = '\0';
    
    std::string request(buffer);
    
    // Parse request
    std::istringstream iss(request);
    std::string cmd, groupId, filename;
    iss >> cmd >> groupId >> filename;
    
    if (cmd == "REQUEST_FILE") {
        // Ask tracker for file path
        std::string pathCmd = "get_file_path " + groupId + " " + filename;
        std::string filePath = sendToTrackerAndGetResponse(pathCmd);
        
        if (filePath.find("ERROR") == 0) {
            std::cerr << filePath << std::endl;
            closesocket(clientSock);
            return 1;
        }
        
        // Send requested file
        if (!sendFile(filePath, clientSock)) {
            std::cerr << "Failed to send file" << std::endl;
        }
    }
    
    closesocket(clientSock);
    return 0;
}

// Thread function for running the peer server
DWORD WINAPI peerServerFunc(LPVOID lpParam) {
    // Create socket for listening
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        std::cerr << "Error creating socket for peer server" << std::endl;
        return 1;
    }
    
    // Bind to port
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));  // Zero initialize
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(clientPort);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    
    // Enable address reuse to avoid "address already in use" errors
    int yes = 1;
    if (setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes)) == SOCKET_ERROR) {
        std::cerr << "setsockopt failed" << std::endl;
    }
    
    // Try to bind, increment port if needed
    int bindAttempts = 0;
    while (bind(listenSock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        bindAttempts++;
        clientPort++;
        serverAddr.sin_port = htons(clientPort);
        
        if (bindAttempts > 100) { // Give up after 100 attempts
            std::cerr << "Could not bind to any port" << std::endl;
            closesocket(listenSock);
            return 1;
        }
    }
    
    // Start listening
    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(listenSock);
        return 1;
    }
    
    // Register with tracker
    if (loggedIn) {
        std::string registerCmd = "register_peer " + std::to_string(clientPort);
        sendToTrackerAndGetResponse(registerCmd);
    }
    
    while (serverRunning) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(listenSock, &readSet);
        
        timeval timeout;
        timeout.tv_sec = 1;  // Check every second if server should stop
        timeout.tv_usec = 0;
        
        if (select(0, &readSet, NULL, NULL, &timeout) > 0) {
            if (FD_ISSET(listenSock, &readSet)) {
                SOCKET clientSock = accept(listenSock, NULL, NULL);
                if (clientSock != INVALID_SOCKET) {
                    SOCKET* param = new SOCKET(clientSock);
                    HANDLE threadHandle = CreateThread(NULL, 0, handleClient, param, 0, NULL);
                    CloseHandle(threadHandle);
                }
            }
        }
    }
    
    closesocket(listenSock);
    return 0;
}

void displayHelp() {
    std::cout << "\nAvailable commands:" << std::endl;
    std::cout << "  create_user <user_id> <password> - Create a new user account" << std::endl;
    std::cout << "  login <user_id> <password> - Log in with your account" << std::endl;
    std::cout << "  create_group <group_id> - Create a new group" << std::endl;
    std::cout << "  join_group <group_id> - Request to join a group" << std::endl;
    std::cout << "  leave_group <group_id> - Leave a group" << std::endl;
    std::cout << "  list_requests <group_id> - List pending join requests for a group" << std::endl;
    std::cout << "  accept_request <group_id> <user_id> - Accept a user's request to join a group" << std::endl;
    std::cout << "  list_groups - List all groups in the network" << std::endl;
    std::cout << "  list_files <group_id> - List all sharable files in a group" << std::endl;
    std::cout << "  upload_file <file_path> <group_id> - Upload a file to a group" << std::endl;
    std::cout << "  download_file <group_id> <file_name> <destination_path> - Download a file" << std::endl;
    std::cout << "  show_downloads - Show your downloads status" << std::endl;
    std::cout << "  stop_share <group_id> <file_name> - Stop sharing a file in a group" << std::endl;
    std::cout << "  logout - Log out from your account" << std::endl;
    std::cout << "  help - Display this help message" << std::endl;
    std::cout << "  exit - Exit the application" << std::endl;
}

void showDownloads() {
    if (downloads.empty()) {
        std::cout << "No downloads" << std::endl;
        return;
    }
    
    std::cout << "Downloads:" << std::endl;
    for (const auto& download : downloads) {
        std::string status = download.second.isCompleted ? "[C]" : "[D]";
        std::string groupId = download.second.groupId;
        std::string filename = download.first;
        
        if (!download.second.isCompleted && download.second.totalSize > 0) {
            // Show progress for in-progress downloads
            int progress = (download.second.downloadedSize * 100) / download.second.totalSize;
            std::cout << status << " [" << groupId << "] " << filename << " - " << progress << "%" << std::endl;
        } else {
            std::cout << status << " [" << groupId << "] " << filename << std::endl;
        }
    }
}

void commandLoop() {
    std::string input;
    
    // Display help at startup
    displayHelp();
    
    while (true) {
        std::cout << "\n>> ";
        std::getline(std::cin, input);

        if (input == "exit") {
            if (loggedIn) {
                sendToTracker("logout");
            }
            break;
        } else if (input == "help") {
            displayHelp();
            continue;
        } else if (input == "show_downloads") {
            showDownloads();
            continue;
        } else if (input.find("upload_file") == 0) {
            // Special handling for upload to check file exists first
            std::istringstream iss(input);
            std::string cmd, filepath, groupId;
            iss >> cmd >> filepath >> groupId;
            
            if (cmd.empty() || filepath.empty() || groupId.empty()) {
                std::cout << "Usage: upload_file <file_path> <group_id>" << std::endl;
                continue;
            }
            
            // Check if file exists before uploading
            std::ifstream fileCheck(filepath);
            if (!fileCheck) {
                std::cout << "Error: File does not exist or cannot be read" << std::endl;
                continue;
            }
            
            // Get file size
            fileCheck.seekg(0, std::ios::end);
            int fileSize = fileCheck.tellg();
            fileCheck.close();
            
            std::cout << "Uploading file..." << std::endl;
            
            // Send to tracker
            sendToTracker(input);
            continue;
        } else if (input.find("download_file") == 0) {
            // Special handling for download
            std::istringstream iss(input);
            std::string cmd, groupId, filename, savePath;
            iss >> cmd >> groupId >> filename >> savePath;
            
            if (cmd.empty() || groupId.empty() || filename.empty() || savePath.empty()) {
                std::cout << "Usage: download_file <group_id> <file_name> <destination_path>" << std::endl;
                continue;
            }
            
            // Notify tracker about download
            sendToTracker(input);
            
            // Run download in the main thread directly instead of creating a new thread
            std::cout << "Starting download..." << std::endl;
            try {
                downloadFile(groupId, filename, savePath);
            } catch (const std::exception& e) {
                std::cerr << "Download failed" << std::endl;
            }
            continue;
        }

        sendToTracker(input);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: client <IP>:<PORT> <tracker_info.txt>\n";
        return 1;
    }

    // Initialize the critical section
    InitializeCriticalSection(&downloadLock);

    std::string ip_port(argv[1]);
    std::string ip = ip_port.substr(0, ip_port.find(':'));
    
    int port;
    try {
        port = std::stoi(ip_port.substr(ip_port.find(':') + 1));
    } catch (const std::exception& e) {
        std::cerr << "Error parsing tracker port: " << e.what() << std::endl;
        DeleteCriticalSection(&downloadLock);
        return 1;
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    trackerSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (trackerSock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed.\n";
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(trackerSock, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection to tracker failed.\n";
        return 1;
    }

    std::cout << "Connected to Tracker " << ip << ":" << port << std::endl;
    std::cout << "Welcome to the P2P File Sharing Client" << std::endl;
    
    // Start peer server
    serverRunning = true;
    serverThreadHandle = CreateThread(NULL, 0, peerServerFunc, NULL, 0, NULL);
    
    commandLoop();
    
    // Stop peer server
    serverRunning = false;
    WaitForSingleObject(serverThreadHandle, 2000);
    CloseHandle(serverThreadHandle);
    
    // Delete the critical section
    DeleteCriticalSection(&downloadLock);
    
    closesocket(trackerSock);
    WSACleanup();
    return 0;
}
