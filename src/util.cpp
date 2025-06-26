#include <string>

std::string uint8_tToHex(const uint8_t *buffer, size_t length)
{
    std::string hexString;
    for (size_t i = 0; i < length; i++)
    {
        char hex[3];                     // flawfinder: ignore
        sprintf(hex, "%02x", buffer[i]); // flawfinder: ignore
        hexString += hex;
    }
    return hexString;
}