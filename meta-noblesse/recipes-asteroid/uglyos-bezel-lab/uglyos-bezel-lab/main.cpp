// SPDX-License-Identifier: MIT
// No direct /dev/input access, system privileges, network, or device writes.
#include <asteroidapp.h>
int main(int argc, char *argv[]) { return AsteroidApp::main(argc, argv); }
