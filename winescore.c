#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_TESTS 14
#define MAX_DETAIL 512

typedef struct {
    const char* name;
    int detected;
    char details[MAX_DETAIL];
} CheckResult;

/* PEB structures */
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef NTSTATUS (WINAPI *NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

/* Helper: safely append to buffer */
int safe_append(char* dest, size_t dest_size, const char* src) {
    size_t len = strlen(dest);
    size_t remain = dest_size - len - 1;
    if (remain > 0) {
        strncat(dest, src, remain);
        dest[dest_size - 1] = '\0';
        return 1;
    }
    return 0;
}

/* Helper: case-insensitive substring search */
int strcontains_ci(const char* haystack, const char* needle) {
    if (!haystack || !needle) return 0;
    char h[512], n[128];
    size_t i;
    for (i = 0; i < sizeof(h)-1 && haystack[i]; i++) 
        h[i] = (char)tolower((unsigned char)haystack[i]);
    h[i] = '\0';
    for (i = 0; i < sizeof(n)-1 && needle[i]; i++) 
        n[i] = (char)tolower((unsigned char)needle[i]);
    n[i] = '\0';
    return strstr(h, n) != NULL;
}

/* Log and attach to a console if ran through a console */
void AttachToConsole() {
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        SetConsoleOutputCP(CP_UTF8);
    }
}

/* Get PEB via NtQueryInformationProcess */
PPEB GetPEB() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;
    
    NtQueryInformationProcess_t NtQueryInformationProcess = 
        (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return NULL;
    
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG retLen = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &retLen);
    if (status == 0) {
        return pbi.PebBaseAddress;
    }
    return NULL;
}

/* 1. Wine-specific exports */
int check_exports(CheckResult* r) {
    r->name = "Wine Exports";
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    int found = 0;
    char buf[256] = "";
    
    if (hK32 && GetProcAddress(hK32, "wine_get_unix_file_name")) {
        found++; safe_append(buf, sizeof(buf), "wine_get_unix_file_name ");
    }
    if (hK32 && GetProcAddress(hK32, "wine_get_dos_file_name")) {
        found++; safe_append(buf, sizeof(buf), "wine_get_dos_file_name ");
    }
    if (hNtdll && GetProcAddress(hNtdll, "wine_get_version")) {
        found++; safe_append(buf, sizeof(buf), "wine_get_version ");
    }
    if (hNtdll && GetProcAddress(hNtdll, "wine_get_host_version")) {
        found++; safe_append(buf, sizeof(buf), "wine_get_host_version ");
    }
    if (hNtdll && GetProcAddress(hNtdll, "wine_server_call")) {
        found++; safe_append(buf, sizeof(buf), "wine_server_call ");
    }
    if (hNtdll && GetProcAddress(hNtdll, "wine_get_build_id")) {
        found++; safe_append(buf, sizeof(buf), "wine_get_build_id ");
    }
    
    if (found > 0) {
        r->detected = 1;
        snprintf(r->details, MAX_DETAIL, "Found %d Wine-specific export(s): %s", found, buf);
    } else {
        r->detected = 0;
        strcpy(r->details, "No Wine exports detected");
    }
    return r->detected;
}

/* 2. MulDiv signed-overflow bug */
int check_muldiv(CheckResult* r) {
    r->name = "MulDiv Bug";
    int result = MulDiv(1, 0x80000000, 0x80000000);
    if (result == 1) {
        r->detected = 1;
        strcpy(r->details, "MulDiv(1, 0x80000000, 0x80000000) returned 1 (Wine behavior; Windows returns 2)");
    } else if (result == 2) {
        r->detected = 0;
        strcpy(r->details, "MulDiv returned 2 (Windows bug behavior)");
    } else {
        r->detected = 0;
        snprintf(r->details, MAX_DETAIL, "MulDiv returned unexpected value: %d", result);
    }
    return r->detected;
}

/* 3. Registry */
int check_registry(CheckResult* r) {
    r->name = "Wine Registry";
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Wine", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        r->detected = 1;
        strcpy(r->details, "HKCU\\Software\\Wine registry key exists");
        return 1;
    }
    r->detected = 0;
    strcpy(r->details, "No Wine registry key found");
    return 0;
}

/* 4. Environment variables */
int check_env(CheckResult* r) {
    r->name = "Environment Variables";
    int found = 0;
    char buf[256] = "";
    char val[256];
    
    if (GetEnvironmentVariableA("WINELOADER", val, sizeof(val)) && val[0]) {
        found++; safe_append(buf, sizeof(buf), "WINELOADER ");
    }
    if (GetEnvironmentVariableA("WINEDLLPATH", val, sizeof(val)) && val[0]) {
        found++; safe_append(buf, sizeof(buf), "WINEDLLPATH ");
    }
    if (GetEnvironmentVariableA("WINEPREFIX", val, sizeof(val)) && val[0]) {
        found++; safe_append(buf, sizeof(buf), "WINEPREFIX ");
    }
    if (GetEnvironmentVariableA("WINEARCH", val, sizeof(val)) && val[0]) {
        found++; safe_append(buf, sizeof(buf), "WINEARCH ");
    }
    
    if (found > 0) {
        r->detected = 1;
        snprintf(r->details, MAX_DETAIL, "Found %d Wine env var(s): %s", found, buf);
    } else {
        r->detected = 0;
        strcpy(r->details, "No Wine environment variables detected");
    }
    return r->detected;
}

/* 5. Module paths */
int check_module_paths(CheckResult* r) {
    r->name = "Module Paths";
    char path[MAX_PATH];
    int found = 0;
    char details[MAX_DETAIL] = "";
    
    if (GetModuleFileNameA(GetModuleHandleA("kernel32.dll"), path, sizeof(path))) {
        if (strcontains_ci(path, ".so") || strcontains_ci(path, "/") || 
            strcontains_ci(path, "\\home\\") || strcontains_ci(path, "\\tmp\\")) {
            found++;
            safe_append(details, sizeof(details), "kernel32: ");
            safe_append(details, sizeof(details), path);
            safe_append(details, sizeof(details), " ");
        }
    }
    if (GetModuleFileNameA(GetModuleHandleA("ntdll.dll"), path, sizeof(path))) {
        if (strcontains_ci(path, ".so") || strcontains_ci(path, "/") || 
            strcontains_ci(path, "\\home\\") || strcontains_ci(path, "\\tmp\\")) {
            found++;
            safe_append(details, sizeof(details), "ntdll: ");
            safe_append(details, sizeof(details), path);
            safe_append(details, sizeof(details), " ");
        }
    }
    if (GetModuleFileNameA(NULL, path, sizeof(path))) {
        if (strcontains_ci(path, "/") || strcontains_ci(path, ".exe.so") || 
            strcontains_ci(path, "\\home\\") || strcontains_ci(path, "\\tmp\\")) {
            found++;
            safe_append(details, sizeof(details), "process: ");
            safe_append(details, sizeof(details), path);
            safe_append(details, sizeof(details), " ");
        }
    }
    
    if (found > 0) {
        r->detected = 1;
        strncpy(r->details, details, MAX_DETAIL-1);
        r->details[MAX_DETAIL-1] = '\0';
    } else {
        r->detected = 0;
        strcpy(r->details, "Module paths appear normal");
    }
    return r->detected;
}

/* 6. System/Windows directory paths */
int check_sysdir(CheckResult* r) {
    r->name = "System Directory";
    r->details[0] = '\0';
    char path[MAX_PATH];
    int found = 0;
    
    if (GetSystemDirectoryA(path, sizeof(path))) {
        if (strcontains_ci(path, "/") || strcontains_ci(path, ".so") || strcontains_ci(path, "\\home\\")) {
            found++;
            safe_append(r->details, MAX_DETAIL, "GetSystemDirectory: ");
            safe_append(r->details, MAX_DETAIL, path);
            safe_append(r->details, MAX_DETAIL, " ");
        }
    }
    if (GetWindowsDirectoryA(path, sizeof(path))) {
        if (strcontains_ci(path, "/") || strcontains_ci(path, ".so") || strcontains_ci(path, "\\home\\")) {
            found++;
            safe_append(r->details, MAX_DETAIL, "GetWindowsDirectory: ");
            safe_append(r->details, MAX_DETAIL, path);
            safe_append(r->details, MAX_DETAIL, " ");
        }
    }
    if (found > 0) {
        r->detected = 1;
    } else {
        r->detected = 0;
        strcpy(r->details, "System directories appear normal");
    }
    return r->detected;
}

/* 7. Unix filesystem access */
int check_unix_fs(CheckResult* r) {
    r->name = "Unix Filesystem";
    HANDLE hFile = CreateFileA("Z:\\proc\\self\\maps", GENERIC_READ, FILE_SHARE_READ, 
                                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        r->detected = 1;
        strcpy(r->details, "Z:\\proc\\self\\maps is accessible (Wine maps Unix root to Z:)");
        return 1;
    }
    r->detected = 0;
    strcpy(r->details, "Unix filesystem paths not accessible");
    return 0;
}

/* 8. Call wine_get_version() */
int check_wine_version(CheckResult* r) {
    r->name = "Wine Version";
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        r->detected = 0;
        strcpy(r->details, "ntdll.dll not found");
        return 0;
    }
    typedef const char* (__cdecl *WineGetVersion)(void);
    WineGetVersion fn = (WineGetVersion)GetProcAddress(hNtdll, "wine_get_version");
    if (fn) {
        const char* ver = fn();
        r->detected = 1;
        snprintf(r->details, MAX_DETAIL, "wine_get_version() returned: %s", ver ? ver : "(null)");
        return 1;
    }
    r->detected = 0;
    strcpy(r->details, "wine_get_version export not present");
    return 0;
}

/* 9. Call wine_get_host_version() */
int check_host_version(CheckResult* r) {
    r->name = "Host OS Version";
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        r->detected = 0;
        strcpy(r->details, "ntdll.dll not found");
        return 0;
    }
    typedef void (__cdecl *WineGetHostVersion)(const char**, const char**);
    WineGetHostVersion fn = (WineGetHostVersion)GetProcAddress(hNtdll, "wine_get_host_version");
    if (fn) {
        const char* sys = NULL;
        const char* release = NULL;
        fn(&sys, &release);
        r->detected = 1;
        snprintf(r->details, MAX_DETAIL, "Host OS: %s, Release: %s", 
                 sys ? sys : "?", release ? release : "?");
        return 1;
    }
    r->detected = 0;
    strcpy(r->details, "wine_get_host_version export not present");
    return 0;
}

/* 10. GetTickCount granularity */
int check_tickcount(CheckResult* r) {
    r->name = "Timer Granularity";
    DWORD t1 = GetTickCount();
    DWORD t2;
    int same_count = 0;
    for (int i = 0; i < 100; i++) {
        t2 = GetTickCount();
        if (t2 == t1) same_count++;
        t1 = t2;
    }
    if (same_count < 10) {
        r->detected = 1;
        snprintf(r->details, MAX_DETAIL, 
                 "GetTickCount changed %d/100 times (high granularity, possible Wine)", 
                 100 - same_count);
    } else {
        r->detected = 0;
        snprintf(r->details, MAX_DETAIL, 
                 "GetTickCount stayed same %d/100 times (low granularity, Windows-like)", 
                 same_count);
    }
    return r->detected;
}

/* 11. Wine-specific system files in System32 */
int check_wine_system_files(CheckResult* r) {
    r->name = "Wine System Files";
    char sysdir[MAX_PATH];
    char path[MAX_PATH];
    int found = 0;
    r->details[0] = '\0';
    
    if (GetSystemDirectoryA(sysdir, sizeof(sysdir))) {
        snprintf(path, sizeof(path), "%s\\wineboot.exe", sysdir);
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            found++; safe_append(r->details, MAX_DETAIL, "wineboot.exe ");
        }
        snprintf(path, sizeof(path), "%s\\winedevice.exe", sysdir);
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            found++; safe_append(r->details, MAX_DETAIL, "winedevice.exe ");
        }
        snprintf(path, sizeof(path), "%s\\winecfg.exe", sysdir);
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            found++; safe_append(r->details, MAX_DETAIL, "winecfg.exe ");
        }
    }
    
    if (found > 0) {
        r->detected = 1;
        safe_append(r->details, MAX_DETAIL, "found in System32");
    } else {
        r->detected = 0;
        strcpy(r->details, "No Wine-specific system files found");
    }
    return r->detected;
}

/* 12. PEB Module Scan */
int check_peb_modules(CheckResult* r) {
    r->name = "PEB Module Scan";
    r->detected = 0;
    r->details[0] = '\0';
    
    PPEB peb = GetPEB();
    if (!peb || !peb->Ldr) {
        strcpy(r->details, "PEB not accessible");
        return 0;
    }
    
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    int found = 0;
    char buf[256];
    
    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)curr - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        
        char name[128] = "";
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            int len = entry->BaseDllName.Length / sizeof(WCHAR);
            if (len >= sizeof(name)) len = sizeof(name)-1;
            for (int i = 0; i < len; i++) {
                name[i] = (char)entry->BaseDllName.Buffer[i];
            }
            name[len] = '\0';
        }
        
        char fullPath[256] = "";
        if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
            int len = entry->FullDllName.Length / sizeof(WCHAR);
            if (len >= sizeof(fullPath)) len = sizeof(fullPath)-1;
            for (int i = 0; i < len; i++) {
                fullPath[i] = (char)entry->FullDllName.Buffer[i];
            }
            fullPath[len] = '\0';
        }
        
        if (strcontains_ci(name, ".so") || strcontains_ci(name, "wine")) {
            found++;
            snprintf(buf, sizeof(buf), "%s ", name);
            safe_append(r->details, MAX_DETAIL, buf);
        }
        if (strcontains_ci(fullPath, "/home/") || strcontains_ci(fullPath, "/tmp/") || 
            strcontains_ci(fullPath, "\\home\\") || strcontains_ci(fullPath, "\\tmp\\")) {
            found++;
            snprintf(buf, sizeof(buf), "(%s) ", fullPath);
            safe_append(r->details, MAX_DETAIL, buf);
        }
        
        curr = curr->Flink;
    }
    
    if (found > 0) {
        r->detected = 1;
        safe_append(r->details, MAX_DETAIL, "detected in PEB module list");
    } else {
        r->detected = 0;
        strcpy(r->details, "PEB module list appears normal");
    }
    return r->detected;
}

/* 13. Manual Export Table Walk */
int check_manual_exports(CheckResult* r) {
    r->name = "Manual Export Walk";
    r->detected = 0;
    r->details[0] = '\0';
    
    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    if (!hMod) {
        strcpy(r->details, "ntdll.dll not found");
        return 0;
    }
    
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        strcpy(r->details, "Invalid DOS signature");
        return 0;
    }
    
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        strcpy(r->details, "Invalid NT signature");
        return 0;
    }
    
    if (nt->OptionalHeader.DataDirectory[0].VirtualAddress == 0) {
        strcpy(r->details, "No export directory");
        return 0;
    }
    
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + 
        nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    uint32_t* names = (uint32_t*)(base + exp->AddressOfNames);
    uint32_t count = exp->NumberOfNames;
    int found = 0;
    char buf[256];
    
    for (uint32_t i = 0; i < count; i++) {
        const char* name = (const char*)(base + names[i]);
        if (name[0] == 'w' && name[1] == 'i' && name[2] == 'n' && 
            name[3] == 'e' && name[4] == '_') {
            found++;
            if (strlen(r->details) < MAX_DETAIL - 64) {
                snprintf(buf, sizeof(buf), "%s ", name);
                safe_append(r->details, MAX_DETAIL, buf);
            }
        }
    }
    
    if (found > 0) {
        r->detected = 1;
        snprintf(buf, sizeof(buf), "(%d wine_ exports found)", found);
        safe_append(r->details, MAX_DETAIL, buf);
    } else {
        r->detected = 0;
        strcpy(r->details, "No wine_ exports in manual PE walk");
    }
    return r->detected;
}

/* 14. Wine Desktop Window class */
int check_wine_desktop(CheckResult* r) {
    r->name = "Wine Desktop Window";
    HWND hWnd = FindWindowA("WineDesktop", NULL);
    if (hWnd) {
        r->detected = 1;
        strcpy(r->details, "Window class 'WineDesktop' found (Wine desktop window)");
    } else {
        r->detected = 0;
        strcpy(r->details, "No WineDesktop window class found");
    }
    return r->detected;
}

int main(void) {
    int confirm = MessageBoxA(NULL, 
        "This program will detect system integrity to check if this program is running under Wine.\n\n"
        "Are you sure you want to continue?",
        "System Integrity Check",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    
    if (confirm != IDYES) {
        return 0;
    }
    
    AttachToConsole();
    
    CheckResult results[MAX_TESTS];
    int score = 0;
    
    /* Run all checks */
    score += check_exports(&results[0]);
    score += check_muldiv(&results[1]);
    score += check_registry(&results[2]);
    score += check_env(&results[3]);
    score += check_module_paths(&results[4]);
    score += check_sysdir(&results[5]);
    score += check_unix_fs(&results[6]);
    score += check_wine_version(&results[7]);
    score += check_host_version(&results[8]);
    score += check_tickcount(&results[9]);
    score += check_wine_system_files(&results[10]);
    score += check_peb_modules(&results[11]);
    score += check_manual_exports(&results[12]);
    score += check_wine_desktop(&results[13]);
    
    /* Build report */
    char report[8192];
    char* p = report;
    int remain = sizeof(report);
    
    #define APPEND(...) do { \
        int n = snprintf(p, remain, __VA_ARGS__); \
        if (n > 0 && n < remain) { p += n; remain -= n; } \
    } while(0)
    
    APPEND("=== WINE DETECTION REPORT ===\n\n");
    APPEND("Score: %d / %d\n\n", score, MAX_TESTS);
    
    if (score == 0) {
        APPEND("Result: CLEAN\n");
        APPEND("No Wine indicators detected. This appears to be native Windows.\n\n");
    } else if (score <= 4) {
        APPEND("Result: SUSPICIOUS\n");
        APPEND("Minor anomalies detected. May be an unusual Windows config or lightly patched Wine.\n\n");
    } else if (score <= 8) {
        APPEND("Result: LIKELY WINE\n");
        APPEND("Multiple Wine indicators detected. Strong evidence of Wine emulation.\n\n");
    } else {
        APPEND("Result: DEFINITE WINE\n");
        APPEND("Extensive Wine indicators detected. This is almost certainly running under Wine.\n\n");
    }
    
    APPEND("--- Individual Checks ---\n\n");
    
    for (int i = 0; i < MAX_TESTS && remain > 200; i++) {
        APPEND("[%s] %s\n  %s\n\n", 
            results[i].detected ? "FAIL" : "PASS",
            results[i].name,
            results[i].details);
    }
    
    report[sizeof(report)-1] = '\0';
    
    printf("%s", report);
    fflush(stdout);
    
    UINT icon = (score > 8) ? MB_ICONERROR : (score > 0) ? MB_ICONWARNING : MB_ICONINFORMATION;
    MessageBoxA(NULL, report, "Detection Results", MB_OK | icon);
    
    return score > 0 ? 1 : 0;
}