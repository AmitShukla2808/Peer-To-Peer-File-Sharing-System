# Peer To Peer File Sharing System

A peer-to-peer file sharing system implemented in C++ that enables efficient and secure file sharing between connected peers. The system utilizes a hybrid architecture that combines the benefits of centralized coordination with decentralized file transfers.

At its core, the system consists of a central tracker server that manages metadata, user accounts, group permissions, and peer discovery, while the actual file transfers occur directly between peers without passing through the central server. This approach optimizes bandwidth usage, reduces server load, and provides scalability while maintaining administrative control.

Key features include:
- User authentication and account management
- Group-based access control for shared files
- Direct peer-to-peer file transfers
- Progress tracking for downloads
- Multi-threaded operation for concurrent connections
- Command-line interface with comprehensive commands

## Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Components](#components)
- [Getting Started](#getting-started)
- [Available Commands](#available-commands)
- [How It Works](#how-it-works)

## Overview

This system enables file sharing between peers with centralized tracking of metadata. The implementation consists of:

- **Tracker Server**: Coordinates users, groups, and file information
- **Client Application**: Connects to tracker and other peers to share files

The system is built for Windows using Winsock API and supports multi-threaded operation for efficient connection handling.

## Architecture

The system follows a hybrid architecture with centralized metadata management and distributed file transfers.

```
┌──────────────────┐                 ┌───────────────┐
│                  │                 │               │
│  Tracker Server  │◄────Register────┤  Client Peer  │
│                  │─────Status─────►│               │
└────────┬─────────┘                 └───────┬───────┘
         │                                   │
         │                                   │
         │         ┌───────────────┐         │
         │         │               │         │
         └─────────┤  Client Peer  │◄────────┘
                   │               │    File Transfer
                   └───────────────┘   (Direct P2P)
```

## Components

### Tracker Server

The tracker manages system metadata without handling actual file transfers:

- Maintains user accounts and authentication
- Tracks groups, memberships, and join requests
- Stores file sharing information
- Provides peer discovery for file transfers
- Multi-threaded client connection handling

**Key Data Structures:**
- `FileInfo`: Stores metadata about shared files
- `Group`: Manages group ownership and memberships
- `PeerInfo`: Tracks peer connection details

### Client Application

The client connects to both the tracker and other peers:

- Communicates with tracker for metadata operations
- Runs a background server for incoming file requests
- Initiates direct P2P file transfers
- Provides command-line interface for user interaction
- Tracks download progress

**Key Data Structures:**
- `DownloadInfo`: Tracks download status and progress
- `PeerInfo`: Stores peer connection details for transfers

## Getting Started

### Starting the Tracker

```bash
tracker.exe <tracker_info.txt> <tracker_no>
```

- `tracker_info.txt`: Text file containing tracker configuration information
- `tracker_no`: Numeric identifier for this tracker instance

The tracker starts listening on port 8001 by default and handles incoming client connections.

### Starting the Client

```bash
client.exe <tracker_IP>:<tracker_PORT> <tracker_info.txt>
```

- `tracker_IP`: IP address of the tracker server
- `tracker_PORT`: Port number where tracker is listening
- `tracker_info.txt`: Text file containing tracker details

On startup, the client displays the available commands and waits for user input.

## Available Commands

### User Management

```
create_user <user_id> <password>
```
- Creates a new user account with the specified ID and password
- Example: `create_user john password123`
- Response: "User created successfully" or error message

```
login <user_id> <password>
```
- Authenticates user and establishes a session
- Automatically registers this peer with the tracker after login
- Example: `login john password123`
- Response: "Login successful" or error message

```
logout
```
- Terminates the current user session
- Unregisters peer information from tracker
- Example: `logout`
- Response: "Logged out successfully"

### Group Management

```
create_group <group_id>
```
- Creates a new group with the current user as owner
- Example: `create_group programming`
- Response: "Group created successfully" or error message

```
join_group <group_id>
```
- Sends a request to join an existing group
- Request must be approved by group owner
- Example: `join_group programming`
- Response: "Join request sent" or error message

```
leave_group <group_id>
```
- Removes current user from group membership
- Group owners cannot leave their groups
- Example: `leave_group programming`
- Response: "Left group successfully" or error message

```
list_requests <group_id>
```
- Lists pending user requests to join a group
- Only available to the group owner
- Example: `list_requests programming`
- Response: List of usernames or error message

```
accept_request <group_id> <user_id>
```
- Approves a user's request to join a group
- Only available to the group owner
- Example: `accept_request programming sarah`
- Response: "User accepted to group" or error message

```
list_groups
```
- Shows all available groups in the network
- Example: `list_groups`
- Response: List of groups with owner information

### File Operations

```
list_files <group_id>
```
- Displays all files shared within a group
- User must be a member of the group
- Example: `list_files programming`
- Response: List of files with size and owner information

```
upload_file <file_path> <group_id>
```
- Registers a file to be shared with a group
- Verifies file existence before registering
- Example: `upload_file C:\Documents\report.pdf programming`
- Response: "File uploaded successfully" or error message

```
download_file <group_id> <file_name> <destination_path>
```
- Downloads a file from another peer in the group
- Shows download progress during transfer
- Example: `download_file programming tutorial.pdf C:\Downloads\`
- Response: Progress updates during download

```
show_downloads
```
- Displays status of all downloads (complete/in-progress)
- Shows progress percentage for ongoing downloads
- Example: `show_downloads`
- Response: List of downloads with status

```
stop_share <group_id> <file_name>
```
- Stops sharing a file in a specific group
- Only works for files owned by the current user
- Example: `stop_share programming report.pdf`
- Response: "File sharing stopped" or error message

### System Commands

```
help
```
- Displays all available commands with descriptions
- Example: `help`
- Response: List of commands and usage information

```
exit
```
- Terminates the client application
- Logs out the user if currently logged in
- Example: `exit`
- Response: Application closes

## How It Works

### User Authentication Flow

```
┌──────────┐                                 ┌─────────┐
│          │   1. create_user/login request  │         │
│  Client  ├─────────────────────────────────►         │
│          │                                 │ Tracker │
│          │   2. Authentication response    │         │
│          │◄─────────────────────────────────┤         │
└──────────┘                                 └─────────┘
      │
      │ 3. If login successful:
      │    - Start peer server 
      │    - Register peer (IP:port)
      ▼
┌─────────────────┐
│                 │
│ Listening for   │
│ file requests   │
│                 │
└─────────────────┘
```

### File Transfer Process

1. **Request:** Client requests a file from a specific group
2. **Verification:** Tracker checks group membership and file existence
3. **Discovery:** Tracker provides IP and port of the peer with the file
4. **Connection:** Requesting client connects directly to the file owner
5. **Transfer:** File is sent in 8KB chunks with progress tracking
6. **Completion:** Download status is updated when finished

```
┌──────────┐    1. File Request    ┌─────────┐
│          ├───────────────────────►         │
│ Client A │    2. Peer Info       │ Tracker │
│          │◄───────────────────────┤         │
└────┬─────┘                       └─────────┘
     │
     │ 3. Direct Connection
     │
     ▼
┌──────────┐    4. File Transfer   
│          │◄─────────────────────┐
│ Client B │                      │ 
│          │                      │
└──────────┘                      │
```

### Group Management Process

```
┌────────────┐                          ┌────────────┐
│            │  1. create_group         │            │
│  Owner     ├──────────────────────────►            │
│  Client    │                          │            │
└────────────┘                          │            │
                                        │  Tracker   │
┌────────────┐  2. join_group request   │            │
│            ├──────────────────────────►            │
│  User      │                          │            │
│  Client    │                          │            │
└────────────┘                          └────────────┘
                                               │
                 3. list_requests              │
┌────────────┐◄──────────────────────────────────┘
│            │
│  Owner     │
│  Client    │  4. accept_request
│            ├───────────────────────────────────►
└────────────┘                          ┌────────────┐
                                        │            │
                                        │  Tracker   │
                                        │            │
                                        └────────────┘
                                               │
                 5. Group access granted       │
┌────────────┐◄──────────────────────────────────┘
│            │
│  User      │
│  Client    │
│            │
└────────────┘
```

### Peer Server Operation

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│  Client Application                                 │
│                                                     │
│  ┌───────────────────┐      ┌────────────────────┐  │
│  │                   │      │                    │  │
│  │  Command Loop     │      │  Peer Server      │  │
│  │  (Main Thread)    │      │  (Background)     │  │
│  │                   │      │                    │  │
│  └─────────┬─────────┘      └──────────┬─────────┘  │
│            │                           │            │
│            ▼                           ▼            │
│  ┌───────────────────┐      ┌────────────────────┐  │
│  │  Tracker          │      │  File Request      │  │
│  │  Communication    │      │  Handler Thread    │  │
│  └───────────────────┘      └────────────────────┘  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Group Management Rules

- Each group has a single owner who administrates membership
- Files can be shared with multiple groups simultaneously
- Users must join groups to access shared files
- Only group members can view files in their groups
- Group owners cannot leave their own groups

---

## Conclusion

This Peer To Peer File Sharing System demonstrates the practical implementation of distributed file sharing with centralized coordination. The hybrid approach offers several advantages over purely centralized or purely decentralized systems:

1. **Reduced Central Server Load**: By transferring files directly between peers, the central server isn't burdened with file transfer traffic
2. **Scalability**: The system can handle an increasing number of peers with minimal additional load on the central tracker
3. **Administrative Control**: The group-based sharing model provides control over who can access shared files
4. **Efficiency**: Direct peer connections minimize network overhead and optimize transfer speeds

The implementation showcases important concepts in networking, multi-threading, file handling, and distributed systems design. While focused on functionality rather than advanced security features, the system provides a solid foundation that could be extended with encryption, integrity verification, and more sophisticated peer discovery mechanisms.

---