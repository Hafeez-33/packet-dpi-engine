#include <iostream>
#include "dpi/version.h"

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
    std::cout << "===========================================\n";
    std::cout << "  Packet DPI Engine v" << dpi::get_version_string() << "\n";
    std::cout << "  Modern C++17 Network Deep Packet Inspection\n";
    std::cout << "===========================================\n";
    std::cout << "Engine initialized in baseline state.\n";
    return 0;
}
