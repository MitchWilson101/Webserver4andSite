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

    // Extract the requested path, ignoring any query parameters
    start += 5; // Position after "GET /"
    size_t end = request.find(" ", start);
    std::string request_path = request.substr(start, end - start);

    // Remove query string if present
    size_t query_pos = request_path.find("?");
    if (query_pos != std::string::npos) {
        request_path = request_path.substr(0, query_pos);
    }

    // Sanitize the path to prevent directory traversal or remote file inclusion
    request_path = sanitize_path(request_path);

    // Determine the file path based on the sanitized request path
    std::string file_path;
    if (request_path.empty() || request_path == "/") {
        file_path = "public/index.html";
    } else {
        file_path = "public/" + request_path;
    }

    // Ensure that file_path does not end in a slash
    if (file_path.back() == '/') {
        file_path += "index.html";  // Default to index.html if path points to a directory
    }

    // Debugging output to trace the file path
    std::cout << "Request Path: " << request_path << std::endl;
    std::cout << "Constructed File Path: " << file_path << std::endl;

    // Check if the file exists and is a regular file
    if (!is_file(file_path)) {
        const char* not_found_response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>";
        send(client_socket, not_found_response, strlen(not_found_response), 0);
        close(client_socket);
        return;
    }

    // Read the file content
    std::string file_content = read_file(file_path);
    if (file_content.empty()) {
        const char* not_found_response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>";
        send(client_socket, not_found_response, strlen(not_found_response), 0);
        close(client_socket);
        return;
    }

    // Determine Content-Type based on file extension
    std::string content_type;
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

    // Build the HTTP response
    std::string http_response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: " + content_type + "\r\n"
        "Content-Length: " + std::to_string(file_content.size()) + "\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "\r\n" + file_content;

    // Send the response
    send(client_socket, http_response.c_str(), http_response.size(), 0);
    close(client_socket);
}




/////////////////////////////////////////////////////////////////////////////////////////////////////


/*void handle_client(int client_socket) {
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


// Extract the requested path from the request
    start += 5; // Position after "GET /"
    size_t end = request.find(" ", start);
    std::string request_path = request.substr(start, end - start);

    // Sanitize the path to prevent directory traversal
    request_path = sanitize_path(request_path);
    

    // Default to index.html if the path is empty
    std::string file_path;
    if (request_path.empty() || request_path == "/") {
        file_path = "public/index.html";
    } else {
        file_path = "public/" + request_path;
    }

   // Debugging output to check paths
    std::cout << "Request Path: " << request_path << std::endl;
    std::cout << "Constructed File Path: " << file_path << std::endl;

  // Check if the file exists and is a regular file
    if (!is_file(file_path)) {
        // 404 Not Found response if the file is missing or if it's a directory
        const char* not_found_response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>";
        send(client_socket, not_found_response, strlen(not_found_response), 0);
        close(client_socket);
        return;
    }

    // Default to index.html if the path is empty
    if (request_path.empty()) {
        file_path = "public/index.html";
    } else {
        // Construct the full file path based on the request
        file_path = "public/" + request_path;
    }
     
     // Debugging output to trace the file path
    std::cout << "Attempting to read file: " << file_path << std::endl;



    // Check if the file exists
    if (!file_exists(file_path)) {
        // 404 Not Found response
        const char* not_found_response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>";
        send(client_socket, not_found_response, strlen(not_found_response), 0);
        close(client_socket);
        return;
    }

    // Read the file content
    std::string file_content = read_file(file_path);
    if (file_content.empty()) {
        // 404 Not Found response if the file is empty or not readable
        const char* not_found_response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>";
        send(client_socket, not_found_response, strlen(not_found_response), 0);
        close(client_socket);
        return;
    }

    // Determine Content-Type based on file extension
    std::string content_type;
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

    // Build the HTTP response
    std::string http_response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: " + content_type + "\r\n"
        "Content-Length: " + std::to_string(file_content.size()) + "\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "\r\n" + file_content;

    // Send the response
    send(client_socket, http_response.c_str(), http_response.size(), 0);
    close(client_socket);
}*/

//////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
