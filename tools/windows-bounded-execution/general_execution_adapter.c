/*
 * LOOM Windows General Adapter Execution v1.
 *
 * The adapter accepts one closed, length-prefixed request on stdin.  It never
 * accepts target identity, arguments, environment, or payload through argv.
 * It snapshots the approved executable into private AppContainer custody,
 * executes it with zero capabilities under a one-process Job Object, and
 * returns one bounded binary response on stdout.
 */
#define wmain loom_windows_host_security_main
#include "../windows-host-security/host_security_probe.c"
#undef wmain

#define GX_REQUEST_MAGIC "LOOMGX1\0"
#define GX_RESPONSE_MAGIC "LOOMGR1\0"
#define GX_OBSERVATION_SCHEMA "loom-windows-general-native-observation/v1"
#define GX_MAX_FRAME (2U * 1024U * 1024U)
#define GX_MAX_TEXT (64U * 1024U)
#define GX_MAX_STDIN (64U * 1024U)
#define GX_MAX_OUTPUT (1024U * 1024U)
#define GX_MAX_ITEMS 64U

typedef struct {
    unsigned char request_hash[32];
    unsigned char target_hash[32];
    DWORD timeout_ms;
    DWORD maximum_output_bytes;
    DWORD argc;
    DWORD envc;
    DWORD stdin_size;
    wchar_t *target;
    wchar_t **argv;
    wchar_t **env_names;
    wchar_t **env_values;
    unsigned char *stdin_bytes;
} gx_request;

typedef struct {
    HANDLE handle;
    const unsigned char *bytes;
    DWORD size;
    DWORD error;
} gx_writer;

static int gx_error(const char *message) {
    fprintf(stderr, "windows-general-adapter: %s\n", message);
    return 2;
}

static int gx_read_exact(HANDLE input, void *buffer, DWORD size) {
    unsigned char *cursor = (unsigned char *)buffer;
    DWORD total = 0;
    while (total < size) {
        DWORD got = 0;
        if (!ReadFile(input, cursor + total, size - total, &got, NULL) || got == 0) return 0;
        total += got;
    }
    return 1;
}

static DWORD gx_u32(const unsigned char raw[4]) {
    return (DWORD)raw[0] | ((DWORD)raw[1] << 8) | ((DWORD)raw[2] << 16) | ((DWORD)raw[3] << 24);
}

static void gx_put_u32(unsigned char raw[4], DWORD value) {
    raw[0] = (unsigned char)(value & 255U);
    raw[1] = (unsigned char)((value >> 8) & 255U);
    raw[2] = (unsigned char)((value >> 16) & 255U);
    raw[3] = (unsigned char)((value >> 24) & 255U);
}

static wchar_t *gx_utf8(const unsigned char *raw, DWORD size) {
    int count;
    wchar_t *value;
    if (size == 0 || size > GX_MAX_TEXT || memchr(raw, 0, size) != NULL) return NULL;
    count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)raw,
                                (int)size, NULL, 0);
    if (count <= 0) return NULL;
    value = (wchar_t *)calloc((size_t)count + 1, sizeof(wchar_t));
    if (value == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)raw,
                            (int)size, value, count) != count) {
        free(value);
        return NULL;
    }
    return value;
}

static wchar_t *gx_read_text(HANDLE input, DWORD *budget) {
    unsigned char length_raw[4];
    unsigned char *raw;
    DWORD size;
    wchar_t *value;
    if (!gx_read_exact(input, length_raw, 4)) return NULL;
    size = gx_u32(length_raw);
    if (size == 0 || size > GX_MAX_TEXT || size > *budget) return NULL;
    raw = (unsigned char *)calloc((size_t)size, 1);
    if (raw == NULL || !gx_read_exact(input, raw, size)) {
        free(raw);
        return NULL;
    }
    *budget -= size;
    value = gx_utf8(raw, size);
    free(raw);
    return value;
}

static void gx_free_request(gx_request *request) {
    DWORD index;
    free(request->target);
    if (request->argv != NULL) {
        for (index = 0; index < request->argc; ++index) free(request->argv[index]);
    }
    if (request->env_names != NULL && request->env_values != NULL) {
        for (index = 0; index < request->envc; ++index) {
            free(request->env_names[index]);
            free(request->env_values[index]);
        }
    }
    free(request->argv);
    free(request->env_names);
    free(request->env_values);
    free(request->stdin_bytes);
    memset(request, 0, sizeof(*request));
}

static int gx_environment_name(const wchar_t *name) {
    const wchar_t *cursor;
    if (*name == L'\0' || *name == L'=') return 0;
    for (cursor = name; *cursor != L'\0'; ++cursor) {
        if (*cursor == L'=' || *cursor < 32) return 0;
    }
    return _wcsicmp(name, L"LOCALAPPDATA") != 0
        && _wcsicmp(name, L"TEMP") != 0 && _wcsicmp(name, L"TMP") != 0;
}

static int gx_parse(gx_request *request) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    unsigned char magic[8];
    unsigned char header[7 * 4];
    DWORD budget = GX_MAX_FRAME;
    DWORD index;
    memset(request, 0, sizeof(*request));
    if (!gx_read_exact(input, magic, 8) || memcmp(magic, GX_REQUEST_MAGIC, 8) != 0) return 0;
    if (!gx_read_exact(input, request->request_hash, 32)
        || !gx_read_exact(input, request->target_hash, 32)
        || !gx_read_exact(input, header, (DWORD)sizeof(header))) return 0;
    if (gx_u32(header) != 1U) return 0;
    request->timeout_ms = gx_u32(header + 4);
    request->maximum_output_bytes = gx_u32(header + 8);
    request->argc = gx_u32(header + 12);
    request->envc = gx_u32(header + 16);
    request->stdin_size = gx_u32(header + 20);
    if (gx_u32(header + 24) != 0U || request->timeout_ms == 0
        || request->timeout_ms > 300000U || request->maximum_output_bytes == 0
        || request->maximum_output_bytes > GX_MAX_OUTPUT || request->argc > GX_MAX_ITEMS
        || request->envc > GX_MAX_ITEMS || request->stdin_size > GX_MAX_STDIN
        || request->stdin_size > budget) return 0;
    request->target = gx_read_text(input, &budget);
    if (request->target == NULL) return 0;
    request->argv = (wchar_t **)calloc(request->argc, sizeof(wchar_t *));
    request->env_names = (wchar_t **)calloc(request->envc, sizeof(wchar_t *));
    request->env_values = (wchar_t **)calloc(request->envc, sizeof(wchar_t *));
    if ((request->argc && request->argv == NULL)
        || (request->envc && (request->env_names == NULL || request->env_values == NULL))) return 0;
    for (index = 0; index < request->argc; ++index) {
        request->argv[index] = gx_read_text(input, &budget);
        if (request->argv[index] == NULL) return 0;
    }
    for (index = 0; index < request->envc; ++index) {
        DWORD earlier;
        request->env_names[index] = gx_read_text(input, &budget);
        request->env_values[index] = gx_read_text(input, &budget);
        if (request->env_names[index] == NULL || request->env_values[index] == NULL
            || !gx_environment_name(request->env_names[index])) return 0;
        for (earlier = 0; earlier < index; ++earlier) {
            if (_wcsicmp(request->env_names[earlier], request->env_names[index]) == 0) return 0;
        }
    }
    request->stdin_bytes = (unsigned char *)calloc((size_t)request->stdin_size + 1, 1);
    if (request->stdin_bytes == NULL
        || !gx_read_exact(input, request->stdin_bytes, request->stdin_size)) return 0;
    {
        unsigned char extra;
        DWORD got = 0;
        BOOL read_ok = ReadFile(input, &extra, 1, &got, NULL);
        if (read_ok && got != 0) return 0;
        if (!read_ok && GetLastError() != ERROR_BROKEN_PIPE
            && GetLastError() != ERROR_HANDLE_EOF) return 0;
    }
    return 1;
}

static wchar_t *gx_environment(gx_request *request, const wchar_t *folder) {
    size_t total = 1;
    wchar_t local_appdata[MAX_WPATH];
    wchar_t temp[MAX_WPATH];
    wchar_t tmp[MAX_WPATH];
    wchar_t **entries;
    wchar_t *block;
    wchar_t *cursor;
    DWORD index;
    if (swprintf_s(local_appdata, MAX_WPATH, L"LOCALAPPDATA=%ls", folder) < 0
        || swprintf_s(temp, MAX_WPATH, L"TEMP=%ls\\Temp", folder) < 0
        || swprintf_s(tmp, MAX_WPATH, L"TMP=%ls\\Temp", folder) < 0) return NULL;
    entries = (wchar_t **)calloc((size_t)request->envc + 3, sizeof(wchar_t *));
    if (entries == NULL) return NULL;
    for (index = 0; index < request->envc; ++index) {
        size_t length = wcslen(request->env_names[index]) + wcslen(request->env_values[index]) + 2;
        entries[index] = (wchar_t *)calloc(length, sizeof(wchar_t));
        if (entries[index] == NULL
            || swprintf_s(entries[index], length, L"%ls=%ls",
                          request->env_names[index], request->env_values[index]) < 0) {
            DWORD free_index;
            for (free_index = 0; free_index <= index; ++free_index) free(entries[free_index]);
            free(entries);
            return NULL;
        }
    }
    entries[request->envc] = _wcsdup(local_appdata);
    entries[request->envc + 1] = _wcsdup(temp);
    entries[request->envc + 2] = _wcsdup(tmp);
    if (entries[request->envc] == NULL || entries[request->envc + 1] == NULL
        || entries[request->envc + 2] == NULL) {
        for (index = 0; index < request->envc + 3; ++index) free(entries[index]);
        free(entries);
        return NULL;
    }
    qsort(entries, (size_t)request->envc + 3, sizeof(wchar_t *), compare_environment_entries);
    for (index = 0; index < request->envc + 3; ++index) total += wcslen(entries[index]) + 1;
    block = (wchar_t *)calloc(total, sizeof(wchar_t));
    if (block == NULL) {
        for (index = 0; index < request->envc + 3; ++index) free(entries[index]);
        free(entries);
        return NULL;
    }
    cursor = block;
    for (index = 0; index < request->envc + 3; ++index) {
        size_t length = wcslen(entries[index]) + 1;
        memcpy(cursor, entries[index], length * sizeof(wchar_t));
        cursor += length;
    }
    *cursor = L'\0';
    for (index = 0; index < request->envc + 3; ++index) free(entries[index]);
    free(entries);
    return block;
}

static size_t gx_quoted_size(const wchar_t *value) {
    size_t size = 3;
    const wchar_t *cursor;
    size_t slashes = 0;
    for (cursor = value; *cursor; ++cursor) {
        if (*cursor == L'\\') { ++slashes; continue; }
        size += *cursor == L'"' ? slashes * 2 + 2 : slashes + 1;
        slashes = 0;
    }
    return size + slashes * 2;
}

static wchar_t *gx_append_quoted(wchar_t *output, const wchar_t *value) {
    const wchar_t *cursor;
    size_t slashes = 0;
    *output++ = L'"';
    for (cursor = value; *cursor; ++cursor) {
        if (*cursor == L'\\') { ++slashes; continue; }
        if (*cursor == L'"') {
            size_t index;
            for (index = 0; index < slashes * 2 + 1; ++index) *output++ = L'\\';
        } else {
            size_t index;
            for (index = 0; index < slashes; ++index) *output++ = L'\\';
        }
        *output++ = *cursor;
        slashes = 0;
    }
    {
        size_t index;
        for (index = 0; index < slashes * 2; ++index) *output++ = L'\\';
    }
    *output++ = L'"';
    *output = L'\0';
    return output;
}

static wchar_t *gx_command(const wchar_t *snapshot, gx_request *request) {
    size_t total = gx_quoted_size(snapshot) + 1;
    wchar_t *command;
    wchar_t *cursor;
    DWORD index;
    for (index = 0; index < request->argc; ++index) total += gx_quoted_size(request->argv[index]) + 1;
    command = (wchar_t *)calloc(total, sizeof(wchar_t));
    if (command == NULL) return NULL;
    cursor = gx_append_quoted(command, snapshot);
    for (index = 0; index < request->argc; ++index) {
        *cursor++ = L' ';
        cursor = gx_append_quoted(cursor, request->argv[index]);
    }
    return command;
}

static DWORD WINAPI gx_write_stdin(LPVOID opaque) {
    gx_writer *writer = (gx_writer *)opaque;
    DWORD total = 0;
    while (total < writer->size) {
        DWORD wrote = 0;
        if (!WriteFile(writer->handle, writer->bytes + total, writer->size - total, &wrote, NULL)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) writer->error = GetLastError();
            break;
        }
        total += wrote;
    }
    CloseHandle(writer->handle);
    writer->handle = NULL;
    return 0;
}

static int gx_drain(HANDLE pipe, unsigned char *output, DWORD maximum,
                    DWORD *used, DWORD *combined, int *open_pipe) {
    DWORD available = 0;
    unsigned char buffer[4096];
    if (!*open_pipe) return 1;
    if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL)) {
        if (GetLastError() == ERROR_BROKEN_PIPE) { *open_pipe = 0; return 1; }
        return 0;
    }
    while (available) {
        DWORD ask = available > sizeof(buffer) ? (DWORD)sizeof(buffer) : available;
        DWORD got = 0;
        DWORD keep;
        DWORD before = *combined;
        if (!ReadFile(pipe, buffer, ask, &got, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) { *open_pipe = 0; return 1; }
            return 0;
        }
        *combined += got;
        keep = before >= maximum ? 0 : got;
        if (keep > maximum - before) keep = maximum - before;
        if (keep) memcpy(output + *used, buffer, keep);
        *used += keep;
        available -= got;
    }
    return 1;
}

static void gx_hex(const unsigned char digest[32], char output[65]) {
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < 32; ++index) {
        output[index * 2] = alphabet[digest[index] >> 4];
        output[index * 2 + 1] = alphabet[digest[index] & 15];
    }
    output[64] = '\0';
}

static int gx_response(gx_request *request, const unsigned char snapshot_hash[32],
                       DWORD exit_code, const char *status, int timed_out, int output_limited,
                       const unsigned char *stdout_bytes, DWORD stdout_size,
                       const unsigned char *stderr_bytes, DWORD stderr_size) {
    char request_hex[65];
    char target_hex[65];
    char snapshot_hex[65];
    char json[1024];
    int json_size;
    unsigned char sizes[12];
    DWORD wrote;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    gx_hex(request->request_hash, request_hex);
    gx_hex(request->target_hash, target_hex);
    gx_hex(snapshot_hash, snapshot_hex);
    json_size = sprintf_s(json, sizeof(json),
        "{\"appcontainer\":true,\"capabilities\":[],\"exit_code\":%lu,"
        "\"job_process_limit\":1,\"network\":\"denied\",\"output_limited\":%s,"
        "\"private_snapshot\":\"byte-identical\",\"request_sha256\":\"%s\","
        "\"schema\":\"%s\",\"snapshot_sha256\":\"%s\",\"status\":\"%s\","
        "\"target_sha256\":\"%s\",\"timed_out\":%s}",
        exit_code, output_limited ? "true" : "false", request_hex,
        GX_OBSERVATION_SCHEMA, snapshot_hex, status, target_hex,
        timed_out ? "true" : "false");
    if (json_size <= 0 || json_size >= (int)sizeof(json)) return gx_error("response JSON overflow");
    gx_put_u32(sizes, (DWORD)json_size);
    gx_put_u32(sizes + 4, stdout_size);
    gx_put_u32(sizes + 8, stderr_size);
    if (!WriteFile(output, GX_RESPONSE_MAGIC, 8, &wrote, NULL) || wrote != 8
        || !WriteFile(output, sizes, 12, &wrote, NULL) || wrote != 12
        || !WriteFile(output, json, (DWORD)json_size, &wrote, NULL) || wrote != (DWORD)json_size
        || (stdout_size && (!WriteFile(output, stdout_bytes, stdout_size, &wrote, NULL) || wrote != stdout_size))
        || (stderr_size && (!WriteFile(output, stderr_bytes, stderr_size, &wrote, NULL) || wrote != stderr_size))) {
        return gx_error("cannot write bounded response");
    }
    return 0;
}

static int gx_execute(gx_request *request) {
    wchar_t profile[96];
    wchar_t *owner = NULL;
    PSID appcontainer_sid = NULL;
    wchar_t *appcontainer_text = NULL;
    PWSTR folder = NULL;
    wchar_t snapshot[MAX_WPATH];
    HANDLE source_handle = NULL;
    HANDLE snapshot_handle = NULL;
    BY_HANDLE_FILE_INFORMATION source_identity;
    BY_HANDLE_FILE_INFORMATION snapshot_identity;
    unsigned char source_hash[32];
    unsigned char snapshot_hash[32];
    HRESULT created;
    SECURITY_ATTRIBUTES pipe_security;
    HANDLE child_stdin = NULL, parent_stdin = NULL;
    HANDLE parent_stdout = NULL, child_stdout = NULL;
    HANDLE parent_stderr = NULL, child_stderr = NULL;
    HANDLE inherited[3];
    SIZE_T attribute_bytes = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    SECURITY_CAPABILITIES capabilities;
    STARTUPINFOEXW startup;
    PROCESS_INFORMATION process;
    HANDLE job = NULL;
    wchar_t *environment = NULL;
    wchar_t *command = NULL;
    gx_writer writer;
    HANDLE writer_thread = NULL;
    unsigned char *stdout_bytes = NULL, *stderr_bytes = NULL;
    DWORD stdout_size = 0, stderr_size = 0, combined = 0;
    DWORD exit_code = 0;
    int stdout_open = 1, stderr_open = 1;
    int timed_out = 0, output_limited = 0, process_done = 0;
    ULONGLONG started;
    const char *status = "exited";

    source_handle = verify_path_components(request->target, 0);
    if (source_handle == NULL) return gx_error("target path contains a reparse point");
    if (!GetFileInformationByHandle(source_handle, &source_identity)) return gx_error("cannot pin target identity");
    hash_file(request->target, source_hash);
    if (!digest_equal(source_hash, request->target_hash)) return gx_error("target hash does not match approval");
    if (!same_identity(source_handle, &source_identity)) return gx_error("target identity changed during verification");

    owner = current_user_sid();
    if (swprintf_s(profile, 96, L"umbra.loom.general.%lu.%llu",
                   GetCurrentProcessId(), (unsigned long long)GetTickCount64()) < 0) {
        return gx_error("cannot name AppContainer profile");
    }
    created = CreateAppContainerProfile(profile, profile, L"LOOM general execution",
                                        NULL, 0, &appcontainer_sid);
    if (FAILED(created)) return gx_error("cannot create fresh AppContainer profile");
    appcontainer_text = sid_string(appcontainer_sid);
    if (GetAppContainerFolderPath(appcontainer_text, &folder) != S_OK || folder == NULL) {
        return gx_error("cannot resolve AppContainer custody folder");
    }
    if (swprintf_s(snapshot, MAX_WPATH, L"%ls\\approved-target.exe", folder) < 0) {
        return gx_error("cannot name private target snapshot");
    }
    if (!CopyFileW(request->target, snapshot, TRUE)) return gx_error("cannot create private target snapshot");
    pin_file_owner(snapshot, owner);
    snapshot_handle = verify_path_components(snapshot, 0);
    if (snapshot_handle == NULL) return gx_error("private target snapshot contains a reparse point");
    if (!GetFileInformationByHandle(snapshot_handle, &snapshot_identity)) return gx_error("cannot pin snapshot identity");
    verify_acl(snapshot_handle, owner, appcontainer_sid);
    hash_file(snapshot, snapshot_hash);
    if (!digest_equal(snapshot_hash, request->target_hash)
        || !same_identity(snapshot_handle, &snapshot_identity)) {
        return gx_error("private target snapshot failed byte or identity verification");
    }

    memset(&pipe_security, 0, sizeof(pipe_security));
    pipe_security.nLength = sizeof(pipe_security);
    pipe_security.bInheritHandle = TRUE;
    if (!CreatePipe(&child_stdin, &parent_stdin, &pipe_security, 0)
        || !CreatePipe(&parent_stdout, &child_stdout, &pipe_security, 0)
        || !CreatePipe(&parent_stderr, &child_stderr, &pipe_security, 0)) {
        return gx_error("cannot create bounded I/O pipes");
    }
    SetHandleInformation(parent_stdin, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(parent_stdout, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(parent_stderr, HANDLE_FLAG_INHERIT, 0);
    inherited[0] = child_stdin; inherited[1] = child_stdout; inherited[2] = child_stderr;
    InitializeProcThreadAttributeList(NULL, 2, 0, &attribute_bytes);
    if (attribute_bytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return gx_error("cannot size process attributes");
    }
    attributes = (LPPROC_THREAD_ATTRIBUTE_LIST)calloc(1, attribute_bytes);
    if (attributes == NULL || !InitializeProcThreadAttributeList(attributes, 2, 0, &attribute_bytes)) {
        return gx_error("cannot initialize process attributes");
    }
    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.AppContainerSid = appcontainer_sid;
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                   &capabilities, sizeof(capabilities), NULL, NULL)
        || !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                      inherited, sizeof(inherited), NULL, NULL)) {
        return gx_error("cannot bind AppContainer or inherited-handle allowlist");
    }
    environment = gx_environment(request, folder);
    command = gx_command(snapshot, request);
    if (environment == NULL || command == NULL) return gx_error("cannot materialize exact invocation");
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_stdin;
    startup.StartupInfo.hStdOutput = child_stdout;
    startup.StartupInfo.hStdError = child_stderr;
    startup.lpAttributeList = attributes;
    if (!CreateProcessW(snapshot, command, NULL, NULL, TRUE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW
                        | CREATE_UNICODE_ENVIRONMENT, environment, folder,
                        &startup.StartupInfo, &process)) {
        return gx_error("cannot create zero-capability target process");
    }
    job = create_containment_job();
    if (!AssignProcessToJobObject(job, process.hProcess)) return gx_error("cannot assign target Job Object");
    close_handle(&child_stdin); close_handle(&child_stdout); close_handle(&child_stderr);
    stdout_bytes = (unsigned char *)calloc(request->maximum_output_bytes, 1);
    stderr_bytes = (unsigned char *)calloc(request->maximum_output_bytes, 1);
    if (stdout_bytes == NULL || stderr_bytes == NULL) return gx_error("cannot allocate bounded output buffers");
    memset(&writer, 0, sizeof(writer));
    writer.handle = parent_stdin;
    writer.bytes = request->stdin_bytes;
    writer.size = request->stdin_size;
    writer_thread = CreateThread(NULL, 0, gx_write_stdin, &writer, 0, NULL);
    if (writer_thread == NULL) return gx_error("cannot start bounded stdin writer");
    parent_stdin = NULL;
    if (ResumeThread(process.hThread) == (DWORD)-1) return gx_error("cannot resume target process");
    started = GetTickCount64();
    while (!process_done || stdout_open || stderr_open) {
        if (!gx_drain(parent_stdout, stdout_bytes, request->maximum_output_bytes,
                      &stdout_size, &combined, &stdout_open)
            || !gx_drain(parent_stderr, stderr_bytes, request->maximum_output_bytes,
                         &stderr_size, &combined, &stderr_open)) {
            TerminateJobObject(job, 0xE003U);
            return gx_error("cannot drain target output");
        }
        if (!process_done && WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) process_done = 1;
        if (!output_limited && combined > request->maximum_output_bytes) {
            output_limited = 1; status = "output-limit";
            TerminateJobObject(job, 0xE001U);
        }
        if (!process_done && !timed_out && GetTickCount64() - started >= request->timeout_ms) {
            timed_out = 1; status = "timeout";
            TerminateJobObject(job, 0xE002U);
        }
        if (!process_done || stdout_open || stderr_open) Sleep(1);
    }
    WaitForSingleObject(writer_thread, 5000);
    if (!GetExitCodeProcess(process.hProcess, &exit_code)) return gx_error("cannot read target exit code");
    if (!timed_out && !output_limited && exit_code != 0) status = "failed";
    gx_response(request, snapshot_hash, exit_code, status, timed_out, output_limited,
                stdout_bytes, stdout_size, stderr_bytes, stderr_size);

    close_handle(&writer_thread); close_handle(&process.hThread); close_handle(&process.hProcess);
    close_handle(&parent_stdout); close_handle(&parent_stderr); close_handle(&job);
    close_handle(&source_handle); close_handle(&snapshot_handle);
    DeleteProcThreadAttributeList(attributes);
    free(attributes); free(environment); free(command); free(stdout_bytes); free(stderr_bytes);
    DeleteFileW(snapshot);
    CoTaskMemFree(folder); FreeSid(appcontainer_sid); free(appcontainer_text); free(owner);
    if (FAILED(DeleteAppContainerProfile(profile))) return gx_error("cannot delete AppContainer profile");
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    gx_request request;
    int result;
    if (argc != 2 || wcscmp(argv[1], L"--execute-v1") != 0) {
        return gx_error("usage: general_execution_adapter.exe --execute-v1");
    }
    if (!gx_parse(&request)) {
        gx_free_request(&request);
        return gx_error("malformed or out-of-profile request frame");
    }
    result = gx_execute(&request);
    gx_free_request(&request);
    return result;
}
