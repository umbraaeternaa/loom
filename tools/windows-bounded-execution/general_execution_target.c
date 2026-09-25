#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


static int is_appcontainer(void) {
    HANDLE token = NULL;
    DWORD value = 0;
    DWORD returned = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    if (!GetTokenInformation(token, TokenIsAppContainer, &value,
                             (DWORD)sizeof(value), &returned)) {
        CloseHandle(token);
        return 0;
    }
    CloseHandle(token);
    return value == 1;
}


static int echo_mode(void) {
    unsigned char buffer[4096];
    DWORD got;
    DWORD wrote;
    wchar_t value[64];
    if (!is_appcontainer()) return 31;
    if (GetEnvironmentVariableW(L"LOOM_ALLOWED", value, 64) == 0
        || wcscmp(value, L"exact") != 0) return 32;
    if (GetEnvironmentVariableW(L"LOOM_PARENT_SECRET", value, 64) != 0) return 33;
    while (ReadFile(GetStdHandle(STD_INPUT_HANDLE), buffer, (DWORD)sizeof(buffer), &got, NULL)
           && got != 0) {
        if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, got, &wrote, NULL)
            || wrote != got) return 34;
    }
    fputs("loom-general-target:echo\n", stderr);
    return 0;
}


static int network_mode(void) {
    WSADATA data;
    SOCKET connection = INVALID_SOCKET;
    struct sockaddr_in target;
    wchar_t port_text[16];
    unsigned long port;
    int connected;
    int error;
    u_long nonblocking = 1;
    if (!is_appcontainer()) return 41;
    if (GetEnvironmentVariableW(L"LOOM_TEST_PORT", port_text, 16) == 0) return 42;
    port = wcstoul(port_text, NULL, 10);
    if (port == 0 || port > 65535) return 43;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 44;
    connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connection == INVALID_SOCKET) {
        error = WSAGetLastError();
        WSACleanup();
        fprintf(stderr, "loom-network-socket-error:%d\n", error);
        return error == WSAEACCES ? 0 : 45;
    }
    if (ioctlsocket(connection, FIONBIO, &nonblocking) == SOCKET_ERROR) return 46;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons((u_short)port);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connected = connect(connection, (struct sockaddr *)&target, (int)sizeof(target));
    error = connected == 0 ? 0 : WSAGetLastError();
    if (connected != 0 && error == WSAEWOULDBLOCK) {
        fd_set writable;
        fd_set exceptional;
        struct timeval timeout;
        int selected;
        int error_size = (int)sizeof(error);
        FD_ZERO(&writable);
        FD_ZERO(&exceptional);
        FD_SET(connection, &writable);
        FD_SET(connection, &exceptional);
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        selected = select(0, NULL, &writable, &exceptional, &timeout);
        if (selected == SOCKET_ERROR) return 49;
        if (selected == 0) {
            error = WSAETIMEDOUT;
        } else if (getsockopt(connection, SOL_SOCKET, SO_ERROR,
                              (char *)&error, &error_size) == SOCKET_ERROR) {
            return 50;
        } else if (error == 0) {
            connected = 0;
        }
    }
    closesocket(connection);
    WSACleanup();
    if (connected == 0) return 47;
    return error == WSAEACCES || error == WSAETIMEDOUT ? 0 : 48;
}


static int spawn_mode(void) {
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    wchar_t command[] = L"C:\\Windows\\System32\\cmd.exe /d /c exit 0";
    if (!is_appcontainer()) return 51;
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = (DWORD)sizeof(startup);
    if (CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", command, NULL, NULL,
                       FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        TerminateProcess(process.hProcess, 52);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 52;
    }
    return 0;
}


static int overflow_mode(void) {
    unsigned char block[4096];
    DWORD wrote;
    unsigned int index;
    memset(block, 'X', sizeof(block));
    for (index = 0; index < 512; ++index) {
        if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), block, (DWORD)sizeof(block), &wrote, NULL)
            || wrote != (DWORD)sizeof(block)) return 0;
    }
    return 61;
}


int wmain(int argc, wchar_t **argv) {
    if (argc == 4 && wcscmp(argv[1], L"--make-link") == 0) {
        if (CreateSymbolicLinkW(argv[3], argv[2], SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) return 0;
        return (int)GetLastError();
    }
    if (argc != 2) return 2;
    if (wcscmp(argv[1], L"echo") == 0) return echo_mode();
    if (wcscmp(argv[1], L"network") == 0) return network_mode();
    if (wcscmp(argv[1], L"spawn") == 0) return spawn_mode();
    if (wcscmp(argv[1], L"overflow") == 0) return overflow_mode();
    if (wcscmp(argv[1], L"timeout") == 0) {
        Sleep(60000);
        return 0;
    }
    return 3;
}
