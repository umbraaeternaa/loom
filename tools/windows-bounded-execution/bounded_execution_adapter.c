/*
 * Fixed CI integration adapter for Windows Bounded Execution v0.
 *
 * The native implementation is deliberately shared with the independently
 * certified Host Security Substrate probe.  This executable is a fixed test
 * action, not a general command runner.
 */
#define wmain loom_windows_host_security_main
#include "../windows-host-security/host_security_probe.c"
#undef wmain

int wmain(int argc, wchar_t **argv) {
    return loom_windows_host_security_main(argc, argv);
}
