#include "dpi/dpi/http_parser.h"
#include <algorithm>
#include <cctype>
#include <cstring>

namespace dpi {

static bool equals_ci(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool HttpParser::parse_request(std::string_view payload, HttpMetadata& out_meta) noexcept {
    if (payload.size() < 10) { // Minimum e.g. "GET / HTTP/1.0"
        return false;
    }

    // 1. Check supported HTTP/1.x methods
    static const char* methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
    };

    const char* matched_method = nullptr;
    size_t method_len = 0;
    for (const char* m : methods) {
        size_t len = std::strlen(m);
        if (payload.size() >= len && payload.substr(0, len) == m) {
            matched_method = m;
            method_len = len - 1; // Exclude trailing space
            break;
        }
    }

    if (!matched_method) {
        return false;
    }

    // 2. Parse Request Line (Method SP URI SP Version CRLF)
    size_t req_line_end = payload.find('\n');
    if (req_line_end == std::string_view::npos) {
        return false;
    }

    std::string_view req_line = payload.substr(0, req_line_end);
    if (!req_line.empty() && req_line.back() == '\r') {
        req_line.remove_suffix(1);
    }

    // Find URI and Version in Request Line
    size_t first_space = req_line.find(' ');
    if (first_space == std::string_view::npos) {
        return false;
    }

    size_t second_space = req_line.rfind(' ');
    if (second_space == std::string_view::npos || second_space <= first_space) {
        return false;
    }

    std::string_view uri = req_line.substr(first_space + 1, second_space - first_space - 1);
    std::string_view version = req_line.substr(second_space + 1);

    // Validate HTTP version
    if (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return false;
    }

    out_meta.method = std::string(matched_method, method_len);
    out_meta.uri = std::string(uri);
    out_meta.version = std::string(version);
    out_meta.has_host = false;
    out_meta.host.clear();

    // 3. Search for Host header in headers section (bounded to max 4096 bytes or end-of-headers)
    size_t headers_start = req_line_end + 1;
    size_t max_scan = std::min<size_t>(payload.size(), 4096);
    std::string_view headers_section = payload.substr(headers_start, max_scan - headers_start);

    bool headers_ended = false;
    size_t pos = 0;
    while (pos < headers_section.size()) {
        size_t line_end = headers_section.find('\n', pos);
        if (line_end == std::string_view::npos) {
            line_end = headers_section.size();
        }

        std::string_view line = headers_section.substr(pos, line_end - pos);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }

        // Empty line indicates end of HTTP headers section
        if (line.empty()) {
            headers_ended = true;
            break;
        }

        size_t colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string_view header_name = line.substr(0, colon);
            if (equals_ci(header_name, "Host")) {
                std::string_view host_val = line.substr(colon + 1);

                // Trim leading whitespace
                while (!host_val.empty() && (host_val.front() == ' ' || host_val.front() == '\t')) {
                    host_val.remove_prefix(1);
                }
                // Trim trailing whitespace
                while (!host_val.empty() && (host_val.back() == ' ' || host_val.back() == '\t')) {
                    host_val.remove_suffix(1);
                }

                // Strip optional port suffix (e.g. "example.com:8080" -> "example.com")
                size_t port_sep = host_val.find(':');
                if (port_sep != std::string_view::npos) {
                    host_val = host_val.substr(0, port_sep);
                }

                if (!host_val.empty()) {
                    out_meta.host = std::string(host_val);
                    out_meta.has_host = true;
                    return true;
                }
            }
        }

        pos = line_end + 1;
    }

    if (out_meta.has_host) {
        return true;
    }

    // If no Host header was found, only consider parsed if headers section fully terminated
    return headers_ended;
}

} // namespace dpi

