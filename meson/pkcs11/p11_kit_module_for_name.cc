#include <p11-kit/p11-kit.h>

int main() {
    void *foo = p11_kit_module_for_name(0, 0);
    return 0;
}
