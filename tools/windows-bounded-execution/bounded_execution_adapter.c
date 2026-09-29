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
    if (argc == 2 && wcscmp(argv[1], L"--close-stdin") == 0) {
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        if (input != NULL && input != INVALID_HANDLE_VALUE) CloseHandle(input);
        Sleep(100);
        return 0;
    }
    return loom_windows_host_security_main(argc, argv);
}
