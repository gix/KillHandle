#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <Psapi.h>
#include <vector>
#include <Shlwapi.h>
#include <strsafe.h>

#include <memory>
#include <array>
#include <exception>
#include <stdexcept>
#include <tuple>
#include <type_traits>
#include <cstdio>
#include <cstdlib>
#include <cstdint>

#pragma warning(push)
#pragma warning(disable: 4995) // <string> is not <Strsafe.h>-safe
#include <string>
#pragma warning(pop)

#pragma warning(3: 4365)

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
typedef NTSTATUS (NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );
typedef NTSTATUS (NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

_NtQuerySystemInformation NtQuerySystemInformation = 0;
_NtDuplicateObject NtDuplicateObject = 0;
_NtQueryObject NtQueryObject = 0;

template<typename To, typename From>
To checked_cast(From const& from);

template<>
int checked_cast<int, size_t>(size_t const& from)
{
    if (from > INT_MAX) throw std::invalid_argument("cast would result in over-/underflow");
    return static_cast<int>(from);
}

template<>
unsigned long checked_cast<unsigned long, size_t>(size_t const& from)
{
    if (from > ULONG_MAX) throw std::invalid_argument("cast would result in over-/underflow");
    return static_cast<unsigned long>(from);
}

template<>
unsigned int checked_cast<unsigned int, int>(int const& from)
{
    if (from < 0) throw std::invalid_argument("cast would result in over-/underflow");
    return static_cast<unsigned int>(from);
}

template<typename T>
T* Malloc(size_t count)
{
    return reinterpret_cast<T*>(malloc(count * sizeof(T)));
}

template<typename T>
T* RawMalloc(size_t size)
{
    return reinterpret_cast<T*>(malloc(size));
}

template<typename T>
T* ReAlloc(T* ptr, size_t count)
{
    return reinterpret_cast<T*>(realloc(ptr, count * sizeof(T)));
}

template<typename T>
T* RawReAlloc(T* ptr, size_t size)
{
    return reinterpret_cast<T*>(realloc(ptr, size));
}

template<>
void* RawReAlloc(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

class handle_ptr
    : public std::unique_ptr<void, BOOL (WINAPI *)(HANDLE)>
{
public:
    handle_ptr(HANDLE handle = NULL)
        : std::unique_ptr<void, BOOL (WINAPI *)(HANDLE)>(handle, CloseHandle)
    { }

    operator HANDLE() { return get(); }
    bool operator ==(HANDLE h) { return h == get(); }
};

class local_free_ptr
    : public std::unique_ptr<void, HLOCAL (__stdcall *)(HLOCAL)>
{
public:
    local_free_ptr(HLOCAL handle = NULL)
        : std::unique_ptr<void, HLOCAL (__stdcall *)(HLOCAL)>(handle, LocalFree)
    { }
};

template<typename T = void>
class malloc_ptr
    : public std::unique_ptr<T, void (*)(void*)>
{
    typedef std::unique_ptr<T, void (*)(void*)> base;
public:
    malloc_ptr(T* ptr = nullptr)
        : base(ptr, std::free)
    {
        EnsureAlloc();
    }

    malloc_ptr(size_t countOrSize, bool useSize = false)
        : base(useSize ? RawMalloc<T>(countOrSize) : Malloc<T>(countOrSize), std::free)
    {
        EnsureAlloc();
    }

    void realloc(size_t countOrSize, bool useSize = false)
    {
        reset(useSize ? RawReAlloc(release(), countOrSize) : ReAlloc(release(), countOrSize));
        EnsureAlloc();
    }

private:
    void EnsureAlloc()
    {
        if (get() == nullptr)
            throw std::bad_alloc();
    }
};

template<>
malloc_ptr<void>::malloc_ptr(size_t size, bool /*useSize*/)
    : malloc_ptr<void>::base(RawMalloc<void>(size), std::free)
{
    EnsureAlloc();
}

template<>
void malloc_ptr<void>::realloc(size_t size, bool /*useSize*/)
{
    reset(RawReAlloc(release(), size));
    EnsureAlloc();
}

class NamedHandle
{
public:
    NamedHandle(std::wstring const& name, HANDLE handle)
        : Name(name), Handle(handle) { }
    std::wstring Name;
    HANDLE Handle;
};

typedef std::vector<NamedHandle> HandleList;
typedef std::vector<DWORD> ProcessIdList;

template<typename T>
T GetLibraryProcAddress(wchar_t const* libraryName, char const* procName)
{
    return reinterpret_cast<T>(GetProcAddress(GetModuleHandleW(libraryName), procName));
}

bool EndsWith(std::wstring const& string, std::wstring const& ending)
{
    if (string.length() < ending.length())
        return false;

    return StrCmpNIW(
        &string[string.length() - ending.length()],
        ending.c_str(),
        checked_cast<int>(ending.length())
        ) == 0;
}

bool EqualsI(std::wstring const& left, std::wstring const& right)
{
    if (left.length() != right.length())
        return false;

    return StrCmpNIW(left.c_str(), right.c_str(), checked_cast<int>(left.length())) == 0;
}

bool LoadProcs()
{
    NtQuerySystemInformation = GetLibraryProcAddress<_NtQuerySystemInformation>(L"ntdll.dll", "NtQuerySystemInformation");
    NtDuplicateObject = GetLibraryProcAddress<_NtDuplicateObject>(L"ntdll.dll", "NtDuplicateObject");
    NtQueryObject = GetLibraryProcAddress<_NtQueryObject>(L"ntdll.dll", "NtQueryObject");

    return
        NtQuerySystemInformation != nullptr &&
        NtDuplicateObject != nullptr &&
        NtQueryObject != nullptr;
}

namespace StringCvt
{
    size_t wcslen_max(wchar_t const* ptr, size_t max)
    {
        size_t len = 0;
        while (len < max && ptr[len] != 0)
            ++len;
        return len;
    }

    size_t ConvertWideToCodepage(
        unsigned codepage, char* out, size_t outSize, wchar_t const* source, size_t sourceSize)
    {
        if (outSize == 0)
            return 0;

        std::memset(out, 0, outSize * sizeof(out[0]));
        ::WideCharToMultiByte(codepage, 0, source, checked_cast<int>(sourceSize), out, checked_cast<int>(outSize), "?", NULL);
        out[outSize-1] = 0;
        return strlen(out);
    }

    size_t EstimateWideToCodepage(unsigned codepage, wchar_t const* source, size_t sourceSize)
    {
        return static_cast<size_t>(::WideCharToMultiByte(codepage, 0, source, checked_cast<int>(sourceSize), nullptr, 0, "?", NULL) + 1);
    }

    class AnsiFromWide {
    public:
        AnsiFromWide() {}
        AnsiFromWide(AnsiFromWide const& source) : buffer(source.buffer) { }
        AnsiFromWide(wchar_t const* source, size_t sourceSize = ~0)
        {
            if (sourceSize == ~0)
                sourceSize = wcslen(source);
            Convert(source, sourceSize);
        }

        void Convert(wchar_t const* source, size_t sourceSize = ~0)
        {
            if (sourceSize == ~0)
                sourceSize = wcslen(source);
            size_t size = EstimateWideToCodepage(CP_ACP, source, sourceSize);
            buffer.resize(size);
            ConvertWideToCodepage(CP_ACP, buffer.data(), size, source, sourceSize);
        }

        operator char const*() const { return GetPtr(); }
        char const* GetPtr() const { return buffer.data(); }
        size_t Length() const { return strlen(GetPtr()); }

    private:
        std::vector<char> buffer;
    };
}

void FormatError(
    DWORD errorCode,
    HMODULE module,
    std::wstring const* customMessage,
    std::string* errorMessageOut)
{
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    if (module != NULL)
        flags |= FORMAT_MESSAGE_FROM_HMODULE;

    wchar_t* messageBuffer = nullptr;
    local_free_ptr messageBufferGuard;
    DWORD result = ::FormatMessageW(
        flags,
        module,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&messageBuffer),
        0,
        NULL);

    std::wstring errorMessage;
    if (result == 0) {
        DWORD err = ::GetLastError();
        result = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            NULL);

        if (result == 0) {
            messageBufferGuard.reset();
            messageBuffer = L"Unable to format error code. Additionally, an error occured formatting the error code of FormatMessage.";
        } else {
            messageBufferGuard.reset(messageBuffer);
        }
    } else {
        messageBufferGuard.reset(messageBuffer);
    }

    SIZE_T size = (wcslen(messageBuffer) + 40) * sizeof(wchar_t);
    local_free_ptr msgWithCodeBuffer(::LocalAlloc(LMEM_ZEROINIT, size));
    ::StringCchPrintfW(
        reinterpret_cast<LPWSTR>(msgWithCodeBuffer.get()),
        ::LocalSize(msgWithCodeBuffer.get()) / sizeof(wchar_t),
        L"[0x%X] %s",
        errorCode,
        messageBuffer);

    wchar_t* msgWithCode = reinterpret_cast<wchar_t*>(msgWithCodeBuffer.get());
    size_t len = wcslen(msgWithCode) - 1;
    while (len > 0 && msgWithCode[len] == '\n' || msgWithCode[len] == '\r')
        --len;
    msgWithCode[len + 1] = 0;

    if (customMessage != nullptr && customMessage->size() > 0)
        *errorMessageOut = StringCvt::AnsiFromWide((*customMessage + msgWithCode).c_str());
    else
        *errorMessageOut = StringCvt::AnsiFromWide(msgWithCode);
}

class NtException : public virtual std::exception
{
public:
    NtException(NTSTATUS status);
    NtException(NTSTATUS status, std::wstring const& message);

    virtual char const* what() const { return message.c_str(); }

private:
    NTSTATUS status;
    std::string message;
};

NtException::NtException(NTSTATUS status)
    : status(status)
{
    FormatError(static_cast<DWORD>(status), GetModuleHandleW(L"ntdll.dll"), nullptr, &this->message);
}

NtException::NtException(NTSTATUS status, std::wstring const& message)
    : status(status)
{
    FormatError(static_cast<DWORD>(status), GetModuleHandleW(L"ntdll.dll"), &message, &this->message);
}

class Win32Exception : public virtual std::exception
{
public:
    Win32Exception();
    Win32Exception(DWORD error);
    Win32Exception(std::wstring const& message);
    Win32Exception(DWORD error, std::wstring const& message);

    virtual char const* what() const { return message.c_str(); }

private:
    DWORD error;
    std::string message;
};

Win32Exception::Win32Exception()
    : error(GetLastError())
{
    FormatError(error, NULL, nullptr, &this->message);
}

Win32Exception::Win32Exception(DWORD error)
    : error(error)
{
    FormatError(error, NULL, nullptr, &this->message);
}

Win32Exception::Win32Exception(std::wstring const& message)
    : error(GetLastError())
{
    FormatError(error, NULL, &message, &this->message);
}

Win32Exception::Win32Exception(DWORD error, std::wstring const& message)
    : error(error)
{
    FormatError(error, NULL, &message, &this->message);
}

std::wstring QueryHandleType(HANDLE handle)
{
    malloc_ptr<OBJECT_TYPE_INFORMATION> objectTypeInfo(0x1000, true);
    NTSTATUS status = NtQueryObject(handle, ObjectTypeInformation, objectTypeInfo.get(), 0x1000, NULL);
    if (!NT_SUCCESS(status))
        throw NtException(status, L"Could not query type of handle via NtQueryObject.");

    return std::wstring(objectTypeInfo->Name.Buffer, checked_cast<unsigned int>(objectTypeInfo->Name.Length / 2));
}

std::wstring QueryHandleName(HANDLE handle)
{
    malloc_ptr<> objectNameInfo(0x1000);
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryObject(
        handle,
        ObjectNameInformation,
        objectNameInfo.get(),
        0x1000,
        &returnLength);

    if (!NT_SUCCESS(status)) {
        if (status != STATUS_INFO_LENGTH_MISMATCH)
            throw NtException(status);

        // Reallocate the buffer and try again.
        objectNameInfo.realloc(returnLength, true);
        status = NtQueryObject(
            handle,
            ObjectNameInformation,
            objectNameInfo.get(),
            returnLength,
            NULL);
    }

    if (!NT_SUCCESS(status))
        throw NtException(status, L"Could not query name of handle via NtQueryObject.");

    UNICODE_STRING objectName = *reinterpret_cast<UNICODE_STRING*>(objectNameInfo.get());
    if (objectName.Length == 0)
        return std::wstring(L"<unnamed>");

    return std::wstring(objectName.Buffer, checked_cast<unsigned int>(objectName.Length / 2));
}

// Translate path with device name to drive letters.
std::wstring NativePathToDosPath(std::wstring nativePath)
{
    int const BufferSize = 512;
    wchar_t temp[BufferSize];
    temp[0] = '\0';

    if (!GetLogicalDriveStringsW(BufferSize - 1, temp))
        throw std::exception();

    wchar_t name[MAX_PATH];
    wchar_t drive[3] = L" :";
    bool found = false;
    wchar_t* p = temp;

    do {
        // Copy the drive letter to the template string
        *drive = *p;

        // Look up each device name
        if (QueryDosDevice(drive, name, MAX_PATH)) {
            size_t nameLength = wcslen(name);

            if (nameLength < MAX_PATH) {
                found =
                    _wcsnicmp(nativePath.c_str(), name, nameLength) == 0 &&
                    nativePath[nameLength] == L'\\';

                if (found) {
                    // Replace device path with DOS path
                    wchar_t tempFile[MAX_PATH];
                    StringCchPrintfW(
                        tempFile,
                        MAX_PATH,
                        L"%s%s",
                        drive,
                        nativePath.c_str() + nameLength);
                    std::wstring dosPath(tempFile);
                    return dosPath;
                }
            }
        }

        // Go to the next NULL character.
        while (*p++)
            ;
    } while (!found && *p); // end of string

    return std::wstring();
}

bool TryGetProcessName(DWORD const processId, std::wstring& processName)
{
    handle_ptr process(OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        processId));

    if (process == NULL)
        return false;

    HMODULE baseModule;
    DWORD bytesNeeded;
    if (!EnumProcessModules(process, &baseModule, sizeof(baseModule), &bytesNeeded))
        return false;

    wchar_t nameBuffer[MAX_PATH] = L"<unknown>";
    GetModuleBaseNameW(process, baseModule, nameBuffer, _countof(nameBuffer));

    processName.assign(nameBuffer);
    return true;
}

template<typename T, typename A>
inline size_t DataSizeOf(std::vector<T, A> const& vec)
{
    return sizeof(vec[0]) * vec.size();
}

ProcessIdList GetProcessIds()
{
    ProcessIdList processIds(1024);
    size_t processCount = 0;

    for (;;) {
        DWORD returnedBytes;
        DWORD bytes = checked_cast<DWORD>(DataSizeOf(processIds));
        if (!EnumProcesses(processIds.data(), bytes, &returnedBytes))
            break;
        if (returnedBytes < bytes) {
            processCount = returnedBytes / sizeof(DWORD);
            break;
        }

        processIds.resize(processIds.size() * 2);
    }

    processIds.resize(processCount);
    processIds.shrink_to_fit();
    return processIds;
}

DWORD FindProcessByName(std::wstring const& name)
{
    ProcessIdList processIds(GetProcessIds());

    for (auto it = processIds.begin(), end = processIds.end(); it != end; ++it) {
        std::wstring processName;
        if (TryGetProcessName(*it, processName) && EndsWith(processName, name))
            return *it;
    }

    return 0;
}

HandleList FindHandles(DWORD processId, HANDLE processHandle, std::wstring fileName)
{
    NTSTATUS status;
    HandleList handles;

    ULONG handleInfoSize = 0x10000;
    malloc_ptr<SYSTEM_HANDLE_INFORMATION> handleInfo(handleInfoSize, true);

    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo.get(),
        handleInfoSize,
        NULL
        )) == STATUS_INFO_LENGTH_MISMATCH) {
        handleInfo.realloc(handleInfoSize *= 2, true);
    }

    if (!NT_SUCCESS(status))
        throw NtException(status, L"NtQuerySystemInformation failed.");

    for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;

        if (handle.ProcessId != processId)
            continue;
        if (handle.GrantedAccess == 0x0012019F)
            continue;

        // Duplicate the handle so we can query it.
        status = NtDuplicateObject(
            processHandle, reinterpret_cast<HANDLE>(handle.Handle), GetCurrentProcess(),
            &dupHandle, 0, 0, 0);
        if (!NT_SUCCESS(status))
            continue;

        handle_ptr h(dupHandle);

        std::wstring type = QueryHandleType(h);
        if (type.compare(L"File") != 0)
            continue;

        std::wstring name = QueryHandleName(h);
        if (!EqualsI(name, fileName))
            continue;

        handles.push_back(
            NamedHandle(NativePathToDosPath(name), reinterpret_cast<HANDLE>(handle.Handle)));
    }

    return handles;
}

// Try to get the device path for the input path. Succeeds only if the target
// file exists.
bool TryGetDevicePath(std::wstring inputPath, std::wstring& devicePath)
{
    handle_ptr targetHandle(CreateFileW(
        inputPath.c_str(),
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL));

    if (targetHandle == NULL)
        return false;

    wchar_t buffer[MAX_PATH] = { 0 };
    if (!GetFinalPathNameByHandle(
            targetHandle.get(),
            buffer,
            MAX_PATH,
            FILE_NAME_NORMALIZED | VOLUME_NAME_NT)) {
        // Do not fail here so we can try with the non-modified path.
        devicePath = inputPath;
    } else {
        devicePath = std::wstring(buffer);
    }

    return true;
}

void KillHandle(HANDLE processHandle, NamedHandle handle)
{
    if (!DuplicateHandle(processHandle, handle.Handle, NULL, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
        fwprintf(
            stderr,
            L"KillHandle: Could not close handle 0x%08IX in process 0x%08IX (%s)!\n",
            handle.Handle,
            processHandle,
            handle.Name.c_str());
        return;
    }

    wprintf(
        L"KillHandle: Killed handle 0x%08IX in process 0x%08IX (%s)\n",
        handle.Handle,
        processHandle,
        handle.Name.c_str());
}

int wmain(int argc, wchar_t* argv[])
{
    std::wstring const defaultProcessName(L"devenv.exe");

    if (argc < 2) {
        fwprintf(
            stderr,
            L"KillHandle <file-path> [<process-name = \"%s\">]",
            argv[0],
            defaultProcessName.c_str());
        return 1;
    }

    std::wstring targetFileName;
    if (!TryGetDevicePath(argv[1], targetFileName))
        // Nothing to do
        return 0;

    std::wstring processName(argc >= 3 ? argv[2] : defaultProcessName);

    try {
        DWORD pid = FindProcessByName(processName);
        if (pid == 0) {
            fwprintf(stderr, L"KillHandle: <%s> process not found.\n", processName.c_str());
            return 1;
        }

        if (!LoadProcs()) {
            fwprintf(stderr, L"KillHandle: Could not load ntdll.dll functions.\n");
            return 1;
        }

        handle_ptr processHandle(OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid));
        if (processHandle == NULL) {
            fwprintf(stderr, L"KillHandle: Could not open process %s:%lu.\n", processName.c_str(), pid);
            return 1;
        }

        HandleList handles = FindHandles(pid, processHandle.get(), targetFileName);
        std::for_each(
            handles.begin(),
            handles.end(),
            [&](NamedHandle& handle) { KillHandle(processHandle.get(), handle); });
    } catch (NtException const& ex) {
        fprintf(stderr, "KillHandle: NT-call failed: %s\n", ex.what());
        return 1;
    } catch (std::exception const& ex) {
        fprintf(stderr, "KillHandle: Caught exception: %s\n", ex.what());
        return 1;
    }

    return 0;
}
