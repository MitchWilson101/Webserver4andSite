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
#include <regex>

int server_socket;
bool keep_running = true;

// Helper function to remove any "../" from the path to prevent path traversal

std::string sanitize_path(const std::string& path) {
    std::string sanitized_path = path;

    // Step 1: Decode URL-encoded characters like %2e, %2f, %5c
    sanitized_path = std::regex_replace(sanitized_path, std::regex("%2e"), ".");
    sanitized_path = std::regex_replace(sanitized_path, std::regex("%2f"), "/");
    sanitized_path = std::regex_replace(sanitized_path, std::regex("%5c"), "\\");

    // Step 2: Replace multiple slashes with a single slash
    sanitized_path = std::regex_replace(sanitized_path, std::regex("/+"), "/");

    // Step 3: Reject paths containing "../" or "..\" patterns
    if (sanitized_path.find("..") != std::string::npos) {
        return "public/index.html";  // Redirect to safe default file
    }

    // Step 4: Ensure path starts with "public/"
    if (sanitized_path.compare(0, 7, "public/") != 0) {
        sanitized_path = "public/" + sanitized_path;
    }

    return sanitized_path;
}



// Function to check if a path is a file and exists
bool is_file(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0 && S_ISREG(buffer.st_mode));
}


// To test php on server.
    std::string execute_php(const std::string& file_path, const std::string& post_data) {
    std::string command = "php-cgi " + file_path;
    std::string result;
    char buffer[128];

    // Open a pipe to run the command and capture its output
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return "<h1>500 Internal Server Error</h1>";
    }

    // Write POST data to the PHP process if available
    if (!post_data.empty()) {
        fwrite(post_data.c_str(), 1, post_data.size(), pipe);
    }

    // Read the output of the PHP script
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
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
    char buffer[4096] = {0};  // Increased buffer size for larger POST data
    read(client_socket, buffer, sizeof(buffer) - 1);
    std::string request(buffer);

    // Determine if it's a GET or POST request
    bool is_get = request.find("GET ") == 0;
    bool is_post = request.find("POST ") == 0;

    // Check for valid request type
    if (!is_get && !is_post) {
        const char* bad_request_response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<h1>400 Bad Request</h1>";
        send(client_socket, bad_request_response, strlen(bad_request_response), 0);
        close(client_socket);
        return;
    }

    // Extract path and query safely
    size_t path_start = is_get ? 4 : 5;  // Position after "GET /" or "POST /"
    size_t path_end = request.find(" ", path_start);
    
    // Check if path_end is valid
    if (path_end == std::string::npos) {
        const char* bad_request_response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<h1>400 Bad Request</h1>";
        send(client_socket, bad_request_response, strlen(bad_request_response), 0);
        close(client_socket);
        return;
    }

    std::string request_path = request.substr(path_start, path_end - path_start);

    // Set default file path
    
    std::string file_path = sanitize_path(request_path);
    // Check if file_path is a directory and default to "index.html" if it is
    struct stat path_stat;
    if (stat(file_path.c_str(), &path_stat) == 0 && S_ISDIR(path_stat.st_mode)) {
        file_path += "/index.html";  // Append index.html if path is a directory
    }

    // Handle POST data extraction
    std::string post_data;
    if (is_post) {
        // Find the start of the POST body safely
        size_t post_data_start = request.find("\r\n\r\n");
        if (post_data_start != std::string::npos) {
            post_data_start += 4; // Move past the "\r\n\r\n"
            post_data = request.substr(post_data_start);
        }
    }

    // Check if it's a PHP file
    bool is_php = file_path.find(".php") != std::string::npos;
    std::string response_content;
    std::string content_type = "text/html";

    if (is_php) {
        if (is_post) {
            // Use POST data with PHP
            response_content = execute_php(file_path, post_data); // Updated execute_php to accept POST data
        } else {
            response_content = execute_php(file_path, "");
        }
    } else {
        // Handle static files and check if the file exists
        if (!is_file(file_path)) {
            const char* not_found_response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>";
            send(client_socket, not_found_response, strlen(not_found_response), 0);
            close(client_socket);
            return;
        }
        response_content = read_file(file_path);
        if (file_path.find(".html") != std::string::npos) content_type = "text/html";
        else if (file_path.find(".css") != std::string::npos) content_type = "text/css";
        else if (file_path.find(".js") != std::string::npos) content_type = "application/javascript";
        else content_type = "application/octet-stream";
    }

    // Build the HTTP response
    std::string http_response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: " + content_type + "\r\n"
        "Content-Length: " + std::to_string(response_content.size()) + "\r\n"
        "X-Frame-Options: SAMEORIGIN \r\n"
        "X-Content-Type-Options: nosniff\r\n"
        
        "X-XSS-Protection: 1; mode=block\r\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
        "\r\n" + response_content;

    // Send the response
    send(client_socket, http_response.c_str(), http_response.size(), 0);
    close(client_socket);
}

//"Content-Security-Policy: script-src 'self';\r\n"  // Allows JavaScript only from the same origin.

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
