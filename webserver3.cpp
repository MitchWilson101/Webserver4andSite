#include <iostream>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <csignal>
#include <sstream>
#include <sys/stat.h>
#include <cstdio>

int server_socket;
bool keep_running = true;

// Helper function to remove any "../" from the path to prevent path traversal
std::string sanitize_path(const std::string& path) {
    std::string sanitized_path = path;

    // Remove any "../" sequences to prevent directory traversal
    size_t pos;
    while ((pos = sanitized_path.find("..")) != std::string::npos) {
        sanitized_path.erase(pos, 2);
    }

    // Remove any URL protocols to prevent remote file inclusion
    if (sanitized_path.find("http://") != std::string::npos || sanitized_path.find("https://") != std::string::npos) {
        sanitized_path = ""; // Set to empty to prevent RFI attempts
    }

    return sanitized_path;
}


// Function to check if a path is a file and exists
bool is_file(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0 && S_ISREG(buffer.st_mode));
}


// To test php on server.
    std::string execute_php(const std::string& file_path) {
    std::string command = "php-cgi " + file_path;
    std::string result;
    char buffer[128];

    // Open a pipe to run the command and capture its output
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return "<h1>500 Internal Server Error</h1>";
    }

    // Skip the first line (the "Content-type" header line)
    bool is_first_line = true;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        if (is_first_line && std::string(buffer).find("Content-type:") != std::string::npos) {
            is_first_line = false;  // Skip this line
            continue;
        }
        result += buffer;
    }

    // Close the pipe
    pclose(pipe);
    return result;
}




bool is_internal_ip(const std::string& host) {
    // Block metadata IP 169.254.169.254
    if (host == "169.254.169.254") {
        return true;
    }
    return false;
}


// Function to check if a file exists
bool file_exists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

// Utility function to read a file's contents into a string
std::string read_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::in | std::ios::binary);
    if (!file) return "";
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}


std::string get_host_from_request(const std::string& request) {
    std::istringstream request_stream(request);
    std::string line;

    // Loop through each line of the request
    while (std::getline(request_stream, line)) {
        // Find the Host header line (case-insensitive check is ideal)
        if (line.find("Host:") == 0) {
            // Extract the Host value (everything after "Host: ")
            return line.substr(6);  // 6 because "Host: " is 6 characters
        }
    }

    // If no Host header is found, return an empty string
    return "";
}



void handle_client(int client_socket) {
    char buffer[1024] = {0};
    read(client_socket, buffer, 1024);
    std::string request(buffer);

    // Verify the request contains "GET /"
    size_t start = request.find("GET /");
    if (start == std::string::npos) {
        // Handle the malformed request gracefully
        const char* bad_request_response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<h1>400 Bad Request</h1>";
        send(client_socket, bad_request_response, strlen(bad_request_response), 0);
        close(client_socket);
        return;
    }

    // Extract the requested path and ignore any query parameters
    start += 5;
    size_t end = request.find(" ", start);
    std::string request_path = request.substr(start, end - start);
    
    // Determine the file path based on the request
    std::string file_path = "public/" + request_path;

    // Check if the file is a PHP script
    bool is_php = file_path.find(".php") != std::string::npos;
    std::string response_content;
    std::string content_type = "text/html";  // Default Content-Type for PHP output

    if (is_php) {
        // Execute PHP and get the output
        response_content = execute_php(file_path); // Run PHP code using php-cgi
    } else {
        // Handle static files
        response_content = read_file(file_path); // Read the file content
        // Adjust Content-Type based on the file type
        if (file_path.find(".html") != std::string::npos) {
            content_type = "text/html";
        } else if (file_path.find(".css") != std::string::npos) {
            content_type = "text/css";
        } else if (file_path.find(".js") != std::string::npos) {
            content_type = "application/javascript";
        } else if (file_path.find(".png") != std::string::npos) {
            content_type = "image/png";
        } else if (file_path.find(".jpg") != std::string::npos || file_path.find(".jpeg") != std::string::npos) {
            content_type = "image/jpeg";
        } else {
            content_type = "application/octet-stream"; // Default for unknown types
        }
    }

    // Build the HTTP response
    std::string http_response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: " + content_type + "\r\n"
        "Content-Length: " + std::to_string(response_content.size()) + "\r\n"
        "X-Frame-Options: ALLOW\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "\r\n" + response_content;

    // Send the response
    send(client_socket, http_response.c_str(), http_response.size(), 0);
    close(client_socket);
}


void handle_signal(int signal) {
    std::cout << "Shutting down server...\n";
    keep_running = false;
    if (server_socket > 0) {
        close(server_socket);
        std::cout << "Server socket closed.\n";
    }
}

int main() {
    signal(SIGINT, handle_signal);  // Catch Ctrl+C to shut down

    // Step 1: Create socket
    server_socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_socket == 0) {
        std::cerr << "Socket creation error" << std::endl;
        return -1;
    }
    // Step 2: Allow the socket to accept both IPv4 and IPv6 (dual-stack mode)
    int option = 0;
    if (setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY, &option, sizeof(option)) != 0) {
        std::cerr << "Failed to disable IPV6_V6ONLY, enabling dual-stack mode" << std::endl;
        return -1;
    }

    // Step 3: Set socket options for port reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "setsockopt failed" << std::endl;
        return -1;
    }

    // Step 4: Bind to an address and port
    struct sockaddr_in6 address;
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;  // Listen on any IPv6 address
    address.sin6_port = htons(8080);  // Bind to port 8080

    if (bind(server_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        return -1;
    }

    // Step 5: Listen for incoming connections
    if (listen(server_socket, 10) < 0) {
        std::cerr << "Listen failed" << std::endl;
        return -1;
    }

    std::cout << "Server running on port 8080...\n";

    // Step 6: Main server loop
    while (keep_running) {
        int client_socket;
        struct sockaddr_in6 client_address;
        socklen_t client_address_len = sizeof(client_address);

        client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_address_len);
        if (client_socket < 0) {
            if (keep_running) {
                std::cerr << "Error accepting connection" << std::endl;
            }
            continue;
        }
           // Handle the client in a separate function
        handle_client(client_socket);

        
    }


    std::cout << "Server stopped successfully.\n";
    return 0;
}
