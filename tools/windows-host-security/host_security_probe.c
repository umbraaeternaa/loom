#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <objbase.h>
#include <sddl.h>
#include <userenv.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


#define PROBE_SCHEMA "loom-windows-host-security-native-probe/v0"
#define MAX_WPATH 32768
#define CHILD_TIMEOUT_MS 20000
#define HRESULT_ALREADY_EXISTS ((HRESULT)0x800700B7L)


static void fail_message(const char *message) {
    fprintf(stderr, "%s\n", message);
    ExitProcess(1);
}


static void fail_win32(const char *message) {
    fprintf(stderr, "%s (win32=%lu)\n", message, GetLastError());
    ExitProcess(1);
}


static void close_handle(HANDLE *value) {
    if (*value != NULL && *value != INVALID_HANDLE_VALUE) {
        CloseHandle(*value);
        *value = NULL;
    }
}


static char *wide_utf8(const wchar_t *value) {
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, NULL, 0, NULL, NULL);
    char *result;
    if (size <= 0) fail_win32("cannot size UTF-8 conversion");
    result = (char *)calloc((size_t)size, 1);
    if (result == NULL) fail_message("out of memory converting UTF-8");
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, result, size, NULL, NULL) <= 0) {
        free(result);
        fail_win32("cannot convert UTF-8");
    }
    return result;
}


static wchar_t *sid_string(PSID sid) {
    LPWSTR converted = NULL;
    wchar_t *copy;
    size_t length;
    if (!IsValidSid(sid)) fail_message("invalid SID returned by Windows");
    if (!ConvertSidToStringSidW(sid, &converted)) fail_win32("cannot stringify SID");
    length = wcslen(converted);
    copy = (wchar_t *)calloc(length + 1, sizeof(wchar_t));
    if (copy == NULL) {
        LocalFree(converted);
        fail_message("out of memory copying SID");
    }
    memcpy(copy, converted, (length + 1) * sizeof(wchar_t));
    LocalFree(converted);
    return copy;
}


static wchar_t *current_user_sid(void) {
    HANDLE token = NULL;
    DWORD needed = 0;
    TOKEN_USER *user = NULL;
    wchar_t *result;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        fail_win32("cannot open current process token");
    }
    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (needed == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        close_handle(&token);
        fail_win32("cannot size current user SID");
    }
    user = (TOKEN_USER *)calloc(1, needed);
    if (user == NULL) {
        close_handle(&token);
        fail_message("out of memory reading current user SID");
    }
    if (!GetTokenInformation(token, TokenUser, user, needed, &needed)) {
        free(user);
        close_handle(&token);
        fail_win32("cannot read current user SID");
    }
    result = sid_string(user->User.Sid);
    free(user);
    close_handle(&token);
    return result;
}


static void hash_file(const wchar_t *path, unsigned char digest[32]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    PUCHAR object = NULL;
    DWORD object_size = 0;
    DWORD hash_size = 0;
    DWORD returned = 0;
    unsigned char buffer[65536];
    DWORD got;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) fail_message("BCryptOpenAlgorithmProvider(SHA-256) failed");
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_size,
                              (ULONG)sizeof(object_size), &returned, 0);
    if (status < 0 || returned != (DWORD)sizeof(object_size)) fail_message("cannot read SHA-256 object size");
    status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_size,
                              (ULONG)sizeof(hash_size), &returned, 0);
    if (status < 0 || hash_size != 32) fail_message("unexpected SHA-256 digest size");
    object = (PUCHAR)calloc(object_size, 1);
    if (object == NULL) fail_message("out of memory creating SHA-256 state");
    status = BCryptCreateHash(algorithm, &hash, object, object_size, NULL, 0, 0);
    if (status < 0) fail_message("BCryptCreateHash failed");

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) fail_win32("cannot open file for SHA-256");
    for (;;) {
        if (!ReadFile(file, buffer, (DWORD)sizeof(buffer), &got, NULL)) fail_win32("cannot hash file bytes");
        if (got == 0) break;
        status = BCryptHashData(hash, buffer, got, 0);
        if (status < 0) fail_message("BCryptHashData failed");
    }
    status = BCryptFinishHash(hash, digest, 32, 0);
    if (status < 0) fail_message("BCryptFinishHash failed");
    close_handle(&file);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    free(object);
}


static int digest_equal(const unsigned char left[32], const unsigned char right[32]) {
    unsigned char difference = 0;
    size_t index;
    for (index = 0; index < 32; ++index) difference |= (unsigned char)(left[index] ^ right[index]);
    return difference == 0;
}


static int handle_is_reparse(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO tag;
    memset(&tag, 0, sizeof(tag));
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, (DWORD)sizeof(tag))) {
        fail_win32("cannot inspect reparse tag");
    }
    return (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}


static HANDLE open_component(const wchar_t *path, int directory) {
    DWORD access = FILE_READ_ATTRIBUTES | READ_CONTROL;
    DWORD flags = FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0);
    HANDLE handle = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, flags, NULL);
    if (handle == INVALID_HANDLE_VALUE) fail_win32("cannot open path component without reparse traversal");
    return handle;
}


static HANDLE verify_path_components(const wchar_t *input, int final_directory) {
    wchar_t *full = (wchar_t *)calloc(MAX_WPATH, sizeof(wchar_t));
    DWORD length;
    DWORD index;
    HANDLE handle = NULL;
    if (full == NULL) fail_message("out of memory resolving path");
    length = GetFullPathNameW(input, MAX_WPATH, full, NULL);
    if (length < 3 || length >= MAX_WPATH || full[1] != L':' || full[2] != L'\\') {
        free(full);
        fail_message("security probe requires one canonical drive-qualified path");
    }
    for (index = 3; index <= length; ++index) {
        int final = index == length;
        if (!final && full[index] != L'\\') continue;
        {
            wchar_t saved = full[index];
            full[index] = L'\0';
            handle = open_component(full, final ? final_directory : 1);
            if (handle_is_reparse(handle)) {
                close_handle(&handle);
                free(full);
                SetLastError(ERROR_REPARSE_TAG_MISMATCH);
                return NULL;
            }
            full[index] = saved;
            if (!final) close_handle(&handle);
        }
    }
    free(full);
    return handle;
}


static int same_identity(HANDLE handle, BY_HANDLE_FILE_INFORMATION *before) {
    BY_HANDLE_FILE_INFORMATION after;
    if (!GetFileInformationByHandle(handle, &after)) fail_win32("cannot re-read handle identity");
    return before->dwVolumeSerialNumber == after.dwVolumeSerialNumber
        && before->nFileIndexHigh == after.nFileIndexHigh
        && before->nFileIndexLow == after.nFileIndexLow
        && before->nFileSizeHigh == after.nFileSizeHigh
        && before->nFileSizeLow == after.nFileSizeLow
        && before->ftLastWriteTime.dwHighDateTime == after.ftLastWriteTime.dwHighDateTime
        && before->ftLastWriteTime.dwLowDateTime == after.ftLastWriteTime.dwLowDateTime;
}


static int sid_is_broad(PSID sid) {
    wchar_t *text = sid_string(sid);
    int broad = wcscmp(text, L"S-1-1-0") == 0
        || wcscmp(text, L"S-1-5-7") == 0
        || wcscmp(text, L"S-1-5-11") == 0
        || wcscmp(text, L"S-1-5-32-545") == 0
        || wcscmp(text, L"S-1-5-32-546") == 0;
    free(text);
    return broad;
}


static void verify_acl(HANDLE handle, const wchar_t *owner_expected, PSID appcontainer_sid) {
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    ACL_SIZE_INFORMATION size;
    wchar_t *owner_text;
    DWORD index;
    int appcontainer_seen = 0;
    DWORD write_mask = GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA
        | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
    DWORD status = GetSecurityInfo(handle, SE_FILE_OBJECT,
                                   OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                   &owner, NULL, &dacl, NULL, &descriptor);
    if (status != ERROR_SUCCESS) {
        SetLastError(status);
        fail_win32("cannot read handle security descriptor");
    }
    if (owner == NULL || dacl == NULL) fail_message("private custody has a null owner or DACL");
    owner_text = sid_string(owner);
    if (wcscmp(owner_text, owner_expected) != 0) fail_message("private custody owner SID drifted");
    free(owner_text);
    memset(&size, 0, sizeof(size));
    if (!GetAclInformation(dacl, &size, (DWORD)sizeof(size), AclSizeInformation)) fail_win32("cannot inspect DACL");
    for (index = 0; index < size.AceCount; ++index) {
        void *raw = NULL;
        ACE_HEADER *header;
        ACCESS_ALLOWED_ACE *allowed;
        PSID sid;
        if (!GetAce(dacl, index, &raw)) fail_win32("cannot inspect DACL ACE");
        header = (ACE_HEADER *)raw;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        allowed = (ACCESS_ALLOWED_ACE *)raw;
        sid = (PSID)&allowed->SidStart;
        if (sid_is_broad(sid) && (allowed->Mask & write_mask) != 0) {
            fail_message("private custody grants broad write access");
        }
        if (EqualSid(sid, appcontainer_sid)) appcontainer_seen = 1;
    }
    if (!appcontainer_seen) fail_message("AppContainer SID is absent from private custody DACL");
    LocalFree(descriptor);
}


static int token_is_appcontainer(void) {
    HANDLE token = NULL;
    DWORD value = 0;
    DWORD returned = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    if (!GetTokenInformation(token, TokenIsAppContainer, &value, (DWORD)sizeof(value), &returned)) {
        close_handle(&token);
        return 0;
    }
    close_handle(&token);
    return value == 1;
}


static int child_mode(const wchar_t *port_text) {
    WSADATA data;
    SOCKET connection = INVALID_SOCKET;
    struct sockaddr_in target;
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    wchar_t command[] = L"C:\\Windows\\System32\\cmd.exe /d /c exit 0";
    unsigned long port = wcstoul(port_text, NULL, 10);
    int connected;
    int network_error;
    if (!token_is_appcontainer()) return 31;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 32;
    connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connection == INVALID_SOCKET) return 33;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons((u_short)port);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    connected = connect(connection, (struct sockaddr *)&target, (int)sizeof(target));
    network_error = connected == 0 ? 0 : WSAGetLastError();
    closesocket(connection);
    WSACleanup();
    if (connected == 0) return 34;
    if (network_error != WSAEACCES) return 38;

    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = (DWORD)sizeof(startup);
    if (CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", command, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        TerminateProcess(process.hProcess, 35);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return 35;
    }
    return 0;
}


static HANDLE create_containment_job(void) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    if (job == NULL) fail_win32("cannot create Job Object");
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, (DWORD)sizeof(limits))) {
        fail_win32("cannot set Job Object process/close limits");
    }
    return job;
}


static SOCKET loopback_listener(u_short *port) {
    WSADATA data;
    SOCKET listener;
    struct sockaddr_in address;
    int size = (int)sizeof(address);
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) fail_message("WSAStartup failed");
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) fail_message("cannot create loopback listener");
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&address, (int)sizeof(address)) == SOCKET_ERROR) {
        fail_message("cannot bind loopback listener");
    }
    if (listen(listener, 1) == SOCKET_ERROR) fail_message("cannot listen on loopback");
    if (getsockname(listener, (struct sockaddr *)&address, &size) == SOCKET_ERROR) {
        fail_message("cannot read loopback listener address");
    }
    *port = ntohs(address.sin_port);
    return listener;
}


static void run_appcontainer_child(const wchar_t *snapshot, PSID appcontainer_sid) {
    SIZE_T bytes = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    SECURITY_CAPABILITIES capabilities;
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION process;
    HANDLE job = NULL;
    SOCKET listener = INVALID_SOCKET;
    u_short port = 0;
    wchar_t command[MAX_WPATH];
    wchar_t environment[2] = {L'\0', L'\0'};
    DWORD wait;
    DWORD exit_code = 0;

    listener = loopback_listener(&port);
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    if (bytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        fail_win32("cannot size process attribute list");
    }
    attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)calloc(1, bytes);
    if (attributes == NULL) fail_message("out of memory creating process attributes");
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) {
        fail_win32("cannot initialize process attribute list");
    }
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.AppContainerSid = appcontainer_sid;
    capabilities.CapabilityCount = 0;
    capabilities.Capabilities = NULL;
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   &capabilities, sizeof(capabilities), NULL, NULL)) {
        fail_win32("cannot bind zero-capability AppContainer attributes");
    }
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.StartupInfo.cb = (DWORD)sizeof(startup);
    startup.lpAttributeList = attributes;
    if (swprintf_s(command, MAX_WPATH, L"\"%ls\" --child %u", snapshot, (unsigned)port) < 0) {
        fail_message("cannot build AppContainer child command");
    }
    if (!CreateProcessW(snapshot, command, NULL, NULL, FALSE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED
                        | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                        environment, NULL, &startup.StartupInfo, &process)) {
        fail_win32("cannot create zero-capability AppContainer process");
    }
    job = create_containment_job();
    if (!AssignProcessToJobObject(job, process.hProcess)) fail_win32("cannot assign AppContainer to Job Object");
    if (ResumeThread(process.hThread) == (DWORD)-1) fail_win32("cannot resume AppContainer process");
    wait = WaitForSingleObject(process.hProcess, CHILD_TIMEOUT_MS);
    if (wait != WAIT_OBJECT_0) {
        TerminateJobObject(job, 36);
        fail_message("AppContainer child timed out");
    }
    if (!GetExitCodeProcess(process.hProcess, &exit_code) || exit_code != 0) {
        fprintf(stderr, "AppContainer child rejected security contract (exit=%lu)\n", exit_code);
        ExitProcess(1);
    }
    close_handle(&process.hThread);
    close_handle(&process.hProcess);
    close_handle(&job);
    DeleteProcThreadAttributeList(attributes);
    free(attributes);
    closesocket(listener);
    WSACleanup();
}


static void prove_kill_on_close(const wchar_t *self) {
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    HANDLE job;
    wchar_t command[MAX_WPATH];
    DWORD wait;
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = (DWORD)sizeof(startup);
    if (swprintf_s(command, MAX_WPATH, L"\"%ls\" --linger", self) < 0) {
        fail_message("cannot build Job Object kill probe command");
    }
    if (!CreateProcessW(self, command, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) {
        fail_win32("cannot create Job Object kill probe");
    }
    job = create_containment_job();
    if (!AssignProcessToJobObject(job, process.hProcess)) fail_win32("cannot assign kill probe to Job Object");
    if (ResumeThread(process.hThread) == (DWORD)-1) fail_win32("cannot resume Job Object kill probe");
    Sleep(100);
    close_handle(&job);
    wait = WaitForSingleObject(process.hProcess, 5000);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 37);
        fail_message("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE did not terminate the process");
    }
    close_handle(&process.hThread);
    close_handle(&process.hProcess);
}


static int probe_mode(void) {
    wchar_t self[MAX_WPATH];
    wchar_t profile[64];
    wchar_t *owner_sid = NULL;
    PSID appcontainer_sid = NULL;
    wchar_t *appcontainer_sid_text = NULL;
    PWSTR folder = NULL;
    wchar_t snapshot[MAX_WPATH];
    wchar_t link_path[MAX_WPATH];
    HANDLE snapshot_handle = NULL;
    BY_HANDLE_FILE_INFORMATION before;
    unsigned char source_hash[32];
    unsigned char snapshot_hash[32];
    HRESULT created;
    char *owner_utf8;
    char *appcontainer_utf8;
    DWORD self_length = GetModuleFileNameW(NULL, self, MAX_WPATH);
    if (self_length == 0 || self_length >= MAX_WPATH) fail_win32("cannot identify native probe executable");
    owner_sid = current_user_sid();
    if (swprintf_s(profile, 64, L"umbra.loom.hostsecurity.%lu.%llu",
                   GetCurrentProcessId(), (unsigned long long)GetTickCount64()) < 0) {
        fail_message("cannot build AppContainer profile name");
    }
    created = CreateAppContainerProfile(profile, profile, L"LOOM native security probe",
                                        NULL, 0, &appcontainer_sid);
    if (FAILED(created)) {
        if (created != HRESULT_ALREADY_EXISTS
            || FAILED(DeriveAppContainerSidFromAppContainerName(profile, &appcontainer_sid))) {
            fail_message("cannot create or derive AppContainer profile");
        }
    }
    appcontainer_sid_text = sid_string(appcontainer_sid);
    if (GetAppContainerFolderPath(profile, &folder) != S_OK || folder == NULL) {
        fail_message("cannot resolve AppContainer profile folder");
    }
    if (swprintf_s(snapshot, MAX_WPATH, L"%ls\\probe-copy.exe", folder) < 0
        || swprintf_s(link_path, MAX_WPATH, L"%ls\\probe-link.exe", folder) < 0) {
        fail_message("cannot build private snapshot path");
    }
    if (!CopyFileW(self, snapshot, TRUE)) fail_win32("cannot create private executable snapshot");
    hash_file(self, source_hash);
    hash_file(snapshot, snapshot_hash);
    if (!digest_equal(source_hash, snapshot_hash)) fail_message("private snapshot bytes diverged");
    snapshot_handle = verify_path_components(snapshot, 0);
    if (snapshot_handle == NULL) fail_message("private snapshot path contains a reparse point");
    memset(&before, 0, sizeof(before));
    if (!GetFileInformationByHandle(snapshot_handle, &before)) fail_win32("cannot read snapshot identity");
    verify_acl(snapshot_handle, owner_sid, appcontainer_sid);
    hash_file(snapshot, snapshot_hash);
    if (!same_identity(snapshot_handle, &before)) fail_message("private snapshot handle identity changed");

    if (!CreateSymbolicLinkW(link_path, snapshot, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        fail_win32("cannot create deliberate reparse-point fixture");
    }
    {
        HANDLE rejected = verify_path_components(link_path, 0);
        if (rejected != NULL || GetLastError() != ERROR_REPARSE_TAG_MISMATCH) {
            close_handle(&rejected);
            fail_message("component path reparse fixture was not rejected");
        }
    }

    run_appcontainer_child(snapshot, appcontainer_sid);
    prove_kill_on_close(self);

    owner_utf8 = wide_utf8(owner_sid);
    appcontainer_utf8 = wide_utf8(appcontainer_sid_text);
    printf("{\"acl_broad_write\":\"denied\",\"appcontainer_sid\":\"%s\","
           "\"capabilities\":[],\"child_process\":\"denied\",\"final_handle\":\"stable\","
           "\"job_kill_on_close\":true,\"job_process_limit\":1,\"network\":\"denied\","
           "\"owner_sid\":\"%s\",\"private_snapshot\":\"byte-identical\","
           "\"reparse_points\":\"denied\",\"schema\":\"%s\","
           "\"token_is_appcontainer\":true}\n",
           appcontainer_utf8, owner_utf8, PROBE_SCHEMA);

    free(owner_utf8);
    free(appcontainer_utf8);
    close_handle(&snapshot_handle);
    DeleteFileW(link_path);
    DeleteFileW(snapshot);
    CoTaskMemFree(folder);
    FreeSid(appcontainer_sid);
    free(appcontainer_sid_text);
    free(owner_sid);
    if (FAILED(DeleteAppContainerProfile(profile))) fail_message("cannot delete AppContainer probe profile");
    return 0;
}


int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && wcscmp(argv[1], L"--json") == 0) return probe_mode();
    if (argc == 3 && wcscmp(argv[1], L"--child") == 0) return child_mode(argv[2]);
    if (argc == 2 && wcscmp(argv[1], L"--linger") == 0) {
        Sleep(60000);
        return 0;
    }
    fprintf(stderr, "usage: host_security_probe.exe --json\n");
    return 2;
}
