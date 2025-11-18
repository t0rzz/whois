#include <iostream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <sstream>
#include <cctype>
#include <regex>
#pragma comment(lib, "ws2_32.lib")

// Function to check if a string is an IP address
bool is_ip_address(const std::string& str) {
    std::regex ip_regex(R"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)");
    return std::regex_match(str, ip_regex);
}

// Function to parse command line arguments
struct Options {
    std::string host = "whois.iana.org";
    int port = 43;
    bool iana = false;
    bool hide_disclaimers = false;
    bool verbose = false;
    bool no_recursion = false;
    bool help = false;
    bool version = false;
    // RIPE flags
    bool l_flag = false;
    bool L_flag = false;
    bool m_flag = false;
    bool M_flag = false;
    bool c_flag = false;
    bool x_flag = false;
    bool b_flag = false;
    bool B_flag = false;
    bool G_flag = false;
    bool d_flag = false;
    std::string i_attr;
    std::string T_type;
    bool K_flag = false;
    bool r_flag = false;
    bool R_flag = false;
    bool a_flag = false;
    std::string s_source;
    std::string g_source_first_last;
    std::string t_type;
    std::string v_type;
    std::string q_version_sources_types;
    std::vector<std::string> objects;
    bool error = false;
    std::string error_msg;
};

Options parse_args(int argc, char* argv[]) {
    Options opts;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--host") {
            if (i + 1 < argc) {
                opts.host = argv[++i];
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 'h'";
            }
        } else if (arg == "-p" || arg == "--port") {
            if (i + 1 < argc) {
                opts.port = std::stoi(argv[++i]);
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 'p'";
            }
        } else if (arg == "-I") {
            opts.iana = true;
        } else if (arg == "-H") {
            opts.hide_disclaimers = true;
        } else if (arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "--no-recursion") {
            opts.no_recursion = true;
        } else if (arg == "--help") {
            opts.help = true;
        } else if (arg == "--version") {
            opts.version = true;
        } else if (arg == "-l") {
            opts.l_flag = true;
        } else if (arg == "-L") {
            opts.L_flag = true;
        } else if (arg == "-m") {
            opts.m_flag = true;
        } else if (arg == "-M") {
            opts.M_flag = true;
        } else if (arg == "-c") {
            opts.c_flag = true;
        } else if (arg == "-x") {
            opts.x_flag = true;
        } else if (arg == "-b") {
            opts.b_flag = true;
        } else if (arg == "-B") {
            opts.B_flag = true;
        } else if (arg == "-G") {
            opts.G_flag = true;
        } else if (arg == "-d") {
            opts.d_flag = true;
        } else if (arg == "-i") {
            if (i + 1 < argc) {
                opts.i_attr = argv[++i];
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 'i'";
            }
        } else if (arg == "-T") {
            if (i + 1 < argc) {
                opts.T_type = argv[++i];
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 'T'";
            }
        } else if (arg == "-K") {
            opts.K_flag = true;
        } else if (arg == "-r") {
            opts.r_flag = true;
        } else if (arg == "-R") {
            opts.R_flag = true;
        } else if (arg == "-a") {
            opts.a_flag = true;
        } else if (arg == "-s") {
            if (i + 1 < argc) {
                opts.s_source = argv[++i];
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 's'";
            }
        } else if (arg == "-g") {
            if (i + 1 < argc) {
                opts.g_source_first_last = argv[++i];
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 'g'";
            }
        } else if (arg == "-t") {
            if (i + 1 < argc) {
                opts.t_type = argv[++i];
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 't'";
            }
        } else if (arg == "-v") {
            if (i + 1 < argc) {
                opts.v_type = argv[++i];
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 'v'";
            }
        } else if (arg == "-q") {
            if (i + 1 < argc) {
                opts.q_version_sources_types = argv[++i];
            } else {
                opts.error = true;
                opts.error_msg = "whois: option requires an argument -- 'q'";
            }
        } else if (arg[0] == '-') {
            opts.error = true;
            opts.error_msg = "whois: invalid option -- '" + std::string(1, arg[1]) + "'";
        } else {
            opts.objects.push_back(arg);
        }
    }
    return opts;
}

// Function to perform whois query
std::string whois_query(const std::string& host, int port, const std::string& query) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "WSAStartup failed";
    }

    struct addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
        WSACleanup();
        return "Invalid address or hostname";
    }

    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        WSACleanup();
        return "Socket creation failed";
    }

    // Set the port
    ((struct sockaddr_in*)result->ai_addr)->sin_port = htons(port);

    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(result);
        closesocket(sock);
        WSACleanup();
        return "Connection failed";
    }

    freeaddrinfo(result);

    // send the entire query plus CRLF in one send; some servers are strict
    std::string message = query + "\r\n";
    send(sock, message.c_str(), (int)message.size(), 0);

    std::string response;
    char buffer[1024];
    int bytesReceived;
    while ((bytesReceived = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        response.append(buffer, bytesReceived);
    }

    closesocket(sock);
    WSACleanup();
    return response;
}

int main(int argc, char* argv[]) {
    Options opts = parse_args(argc, argv);

    if (opts.error) {
        std::cerr << opts.error_msg << std::endl;
        opts.help = true;
    }

    if (opts.version) {
        std::cout << "whois version 1.0\n";
        return 0;
    }

    if (!opts.t_type.empty()) {
        std::string result = whois_query("whois.ripe.net", 43, "-t " + opts.t_type);
        std::cout << result << std::endl;
        return 0;
    }

    if (!opts.v_type.empty()) {
        std::string result = whois_query("whois.ripe.net", 43, "-v " + opts.v_type);
        std::cout << result << std::endl;
        return 0;
    }

    if (!opts.q_version_sources_types.empty()) {
        std::string result = whois_query("whois.ripe.net", 43, "-q " + opts.q_version_sources_types);
        std::cout << result << std::endl;
        return 0;
    }

    if (opts.objects.empty()) {
        opts.help = true;
    }

    if (opts.help) {
        std::cout << "Usage: whois [OPTION]... OBJECT...\n\n";
        std::cout << "Options:\n";
        std::cout << "  -h HOST, --host HOST   connect to server HOST\n";
        std::cout << "  -p PORT, --port PORT   connect to PORT\n";
        std::cout << "  -I                     query whois.iana.org and follow its referral\n";
        std::cout << "  -H                     hide legal disclaimers\n";
        std::cout << "      --verbose        explain what is being done\n";
        std::cout << "      --no-recursion   disable recursion from registry to registrar servers\n";
        std::cout << "      --help           display this help and exit\n";
        std::cout << "      --version        output version information and exit\n\n";
        std::cout << "These flags are supported by whois.ripe.net and some RIPE-like servers:\n";
        std::cout << "  -l                     find the one level less specific match\n";
        std::cout << "  -L                     find all levels less specific matches\n";
        std::cout << "  -m                     find all one level more specific matches\n";
        std::cout << "  -M                     find all levels of more specific matches\n";
        std::cout << "  -c                     find the smallest match containing a mnt-irt attribute\n";
        std::cout << "  -x                     exact match\n";
        std::cout << "  -b                     return brief IP address ranges with abuse contact\n";
        std::cout << "  -B                     turn off object filtering (show email addresses)\n";
        std::cout << "  -G                     turn off grouping of associated objects\n";
        std::cout << "  -d                     return DNS reverse delegation objects too\n";
        std::cout << "  -i ATTR[,ATTR]...      do an inverse look-up for specified ATTRibutes\n";
        std::cout << "  -T TYPE[,TYPE]...      only look for objects of TYPE\n";
        std::cout << "  -K                     only primary keys are returned\n";
        std::cout << "  -r                     turn off recursive look-ups for contact information\n";
        std::cout << "  -R                     force to show local copy of the domain object even\n";
        std::cout << "                         if it contains referral\n";
        std::cout << "  -a                     also search all the mirrored databases\n";
        std::cout << "  -s SOURCE[,SOURCE]...  search the database mirrored from SOURCE\n";
        std::cout << "  -g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST\n";
        std::cout << "  -t TYPE                request template for object of TYPE\n";
        std::cout << "  -v TYPE                request verbose template for object of TYPE\n";
        std::cout << "  -q [version|sources|types]  query specified server info\n";
        return 0;
    }

    // Adjust default host for IPs
    if (!opts.objects.empty() && opts.host == "whois.iana.org" && is_ip_address(opts.objects[0])) {
        opts.host = "whois.arin.net";
    }

    // Build query prefix from flags
    std::string query_prefix;
    if (opts.l_flag) query_prefix += "-l ";
    if (opts.L_flag) query_prefix += "-L ";
    if (opts.m_flag) query_prefix += "-m ";
    if (opts.M_flag) query_prefix += "-M ";
    if (opts.c_flag) query_prefix += "-c ";
    if (opts.x_flag) query_prefix += "-x ";
    if (opts.b_flag) query_prefix += "-b ";
    if (opts.B_flag) query_prefix += "-B ";
    if (opts.G_flag) query_prefix += "-G ";
    if (opts.d_flag) query_prefix += "-d ";
    if (!opts.i_attr.empty()) query_prefix += "-i " + opts.i_attr + " ";
    if (!opts.T_type.empty()) query_prefix += "-T " + opts.T_type + " ";
    if (opts.K_flag) query_prefix += "-K ";
    if (opts.r_flag) query_prefix += "-r ";
    if (opts.R_flag) query_prefix += "-R ";
    if (opts.a_flag) query_prefix += "-a ";
    if (!opts.s_source.empty()) query_prefix += "-s " + opts.s_source + " ";
    if (!opts.g_source_first_last.empty()) query_prefix += "-g " + opts.g_source_first_last + " ";
    if (!opts.t_type.empty()) query_prefix += "-t " + opts.t_type + " ";
    if (!opts.v_type.empty()) query_prefix += "-v " + opts.v_type + " ";
    if (!opts.q_version_sources_types.empty()) query_prefix += "-q " + opts.q_version_sources_types + " ";

    std::string current_host = opts.host;

    for (const auto& obj : opts.objects) {
        std::string query;
        if (is_ip_address(obj) && query_prefix.empty()) {
            query = "n " + obj;
        } else {
            query = query_prefix + obj;
        }
        std::string result;

        std::string current_host = opts.host;

        // For domains, follow referral from IANA by default
        if (!opts.iana && !is_ip_address(obj) && !opts.no_recursion && opts.host == "whois.iana.org") {
            if (opts.verbose) std::cout << "Querying whois.iana.org for " << obj << std::endl;
            std::string iana_result = whois_query("whois.iana.org", 43, obj);
            // Parse referral
            size_t refer_pos = iana_result.find("refer:");
            if (refer_pos != std::string::npos) {
                size_t start = iana_result.find(":", refer_pos) + 1;
                size_t end = iana_result.find("\n", start);
                std::string referral = iana_result.substr(start, end - start);
                // Trim whitespace
                referral.erase(referral.begin(), std::find_if(referral.begin(), referral.end(), [](int ch) { return !std::isspace(ch); }));
                referral.erase(std::find_if(referral.rbegin(), referral.rend(), [](int ch) { return !std::isspace(ch); }).base(), referral.end());
                current_host = referral;
                if (opts.verbose) std::cout << "Following referral to " << current_host << std::endl;
            } else {
                // No referral, use IANA result
                result = iana_result;
                std::cout << result << std::endl;
                continue;
            }
        }

        if (opts.iana && !opts.no_recursion) {
            if (opts.verbose) std::cout << "Querying whois.iana.org for " << obj << std::endl;
            std::string iana_result = whois_query("whois.iana.org", 43, obj);
            // Parse referral
            size_t refer_pos = iana_result.find("refer:");
            if (refer_pos != std::string::npos) {
                size_t start = iana_result.find(":", refer_pos) + 1;
                size_t end = iana_result.find("\n", start);
                std::string referral = iana_result.substr(start, end - start);
                // Trim whitespace
                referral.erase(referral.begin(), std::find_if(referral.begin(), referral.end(), [](int ch) { return !std::isspace(ch); }));
                referral.erase(std::find_if(referral.rbegin(), referral.rend(), [](int ch) { return !std::isspace(ch); }).base(), referral.end());
                current_host = referral;
                if (opts.verbose) std::cout << "Following referral to " << current_host << std::endl;
            }
            result = whois_query(current_host, opts.port, query);
        } else {
            if (opts.verbose) std::cout << "Querying " << current_host << " for " << query << std::endl;
            result = whois_query(current_host, opts.port, query);
        }

        // Follow to registrar if not no_recursion and for domains
        if (!opts.no_recursion && !is_ip_address(obj)) {
            size_t reg_whois_pos = result.find("Registrar WHOIS Server:");
            if (reg_whois_pos != std::string::npos) {
                size_t start = result.find(":", reg_whois_pos) + 1;
                size_t end = result.find("\n", start);
                std::string reg_server = result.substr(start, end - start);
                // Trim
                reg_server.erase(reg_server.begin(), std::find_if(reg_server.begin(), reg_server.end(), [](int ch) { return !std::isspace(ch); }));
                reg_server.erase(std::find_if(reg_server.rbegin(), reg_server.rend(), [](int ch) { return !std::isspace(ch); }).base(), reg_server.end());
                if (!reg_server.empty() && reg_server != current_host) {
                    std::string upper_obj = obj;
                    std::transform(upper_obj.begin(), upper_obj.end(), upper_obj.begin(), ::toupper);
                    // Try several query formats for registrar servers until one returns a valid result
                    std::vector<std::string> candidates = {
                        obj,
                        upper_obj,
                        "domain " + obj,
                        "domain " + upper_obj,
                        "domain=" + obj,
                        "domain=" + upper_obj,
                        "domain: " + obj,
                        "domain: " + upper_obj
                    };

                    for (const auto &reg_query : candidates) {
                        if (opts.verbose) std::cout << "Querying registrar " << reg_server << " for '" << reg_query << "'" << std::endl;
                        std::string reg_result = whois_query(reg_server, opts.port, reg_query);
                        if (reg_result.empty()) continue;
                        if (reg_result.find("Invalid") == std::string::npos) {
                            result += "\n" + reg_result;
                            break;
                        }
                    }
                }
            }
        }

        if (opts.hide_disclaimers) {
            // Simple filter: remove lines starting with % or # or comments
            std::string filtered;
            std::istringstream iss(result);
            std::string line;
            while (std::getline(iss, line)) {
                if (line.empty() || (line[0] != '%' && line[0] != '#' && line.find("comment:") == std::string::npos)) {
                    filtered += line + "\n";
                }
            }
            result = filtered;
        }

        std::cout << result << std::endl;
    }

    return 0;
}