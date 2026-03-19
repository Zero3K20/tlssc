#include <string>
#include <sstream>
#include <iomanip>

// Decodes a chunked HTTP body. Input is the raw body (after \r\n\r\n).
// Returns the decoded data (no chunk headers or footers).
std::string decode_chunked_body(const std::string& chunked) {
    std::string out;
    size_t pos = 0;
    while (pos < chunked.size()) {
        // Find next \r\n
        size_t line_end = chunked.find("\r\n", pos);
        if (line_end == std::string::npos)
            break;
        // Parse chunk size (hex)
        std::istringstream iss(chunked.substr(pos, line_end - pos));
        size_t chunk_size = 0;
        iss >> std::hex >> chunk_size;
        if (chunk_size == 0)
            break; // end of chunks
        pos = line_end + 2;
        if (pos + chunk_size > chunked.size())
            break; // incomplete
        out.append(chunked, pos, chunk_size);
        pos += chunk_size;
        // Skip trailing \r\n after chunk data
        if (chunked.substr(pos, 2) == "\r\n")
            pos += 2;
    }
    return out;
}
