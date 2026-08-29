#include <iostream>
#include <cassert>
#include "dpi/version.h"

int main() {
    std::cout << "[TEST] Running packet-dpi-engine foundation test suite...\n";

    // Test 1: Version check
    assert(!dpi::get_version_string().empty());
    assert(dpi::Version::MAJOR == 0);
    assert(dpi::Version::MINOR == 1);
    assert(dpi::Version::PATCH == 0);

    std::cout << "[TEST] All foundation tests passed successfully.\n";
    return 0;
}
