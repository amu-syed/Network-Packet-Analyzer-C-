#include <iostream>
#include <string>
#include <limits> // Needed for input validation

// 1. Struct: Defines the blueprint for a network data packet
struct NetworkPacket {
    std::string sourceIP;
    std::string destIP;
    int port;
    bool isFlagged;
};

// 2. Pointers: We pass the packet by memory address (NetworkPacket* packet).
// This allows the function to analyze it efficiently and permanently modify the 'isFlagged' status.
void analyzePacket(NetworkPacket* packet) {
    std::cout << "\n[*] Analyzing traffic from " << packet->sourceIP
              << " to " << packet->destIP << " on Port " << packet->port << "...\n";

    // Basic threat detection logic: Flag insecure plaintext ports
    if (packet->port == 21 || packet->port == 23) {
        packet->isFlagged = true;
        std::cout << "[!] ALERT: Insecure protocol detected (FTP/Telnet). Connection flagged!\n";
    } else if (packet->port == 443) {
        packet->isFlagged = false;
        std::cout << "[+] Connection uses HTTPS. Traffic appears secure.\n";
    } else {
        packet->isFlagged = false;
        std::cout << "[ ] Standard traffic. No immediate threats detected.\n";
    }
}

int main() {
    std::cout << "--- Enterprise Network Packet Analyzer ---\n";
    int choice;

    // 3. Input validation: A robust while loop that catches incorrect data types
    while (true) {
        std::cout << "\n1. Intercept New Packet\n2. Exit System\nSelect an option: ";
        std::cin >> choice;

        // If the user types a letter instead of a number, this catches the error
        if (std::cin.fail() || (choice != 1 && choice != 2)) {
            std::cin.clear(); // Clear the error state
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard the bad input
            std::cout << "[-] Invalid input. Please enter 1 or 2.\n";
            continue;
        }

        if (choice == 2) {
            std::cout << "Shutting down analyzer...\n";
            break;
        }

        // Instantiate the struct
        NetworkPacket currentPacket;

        std::cout << "Enter Source IP (e.g., 192.168.1.5): ";
        std::cin >> currentPacket.sourceIP;
        std::cout << "Enter Destination IP (e.g., 10.0.0.1): ";
        std::cin >> currentPacket.destIP;
        std::cout << "Enter Target Port (e.g., 443): ";
        std::cin >> currentPacket.port;

        // Pass the memory address of our struct to the function using the & operator
        analyzePacket(&currentPacket);
    }

    return 0;
}
