#include <stdio.h>
#include <string.h>
/* A harmless build fixture. FirmwareLens never executes this program. */
int main(int argc, char **argv) {
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "FirmwareLens synthetic fixture: %.64s", argc > 1 ? argv[1] : "lab");
    return puts(buffer) < 0;
}
