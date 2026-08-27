#pragma comment(lib, "tdh.lib")

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <tlhelp32.h>
#include <csignal>
#include <sstream>
#include <map>
#include <optional>
#include <cwctype>

// D3D12 Manifest Provider GUID: 5d8087dd-3a9b-4f56-90df-49196cdc4f11
// D3D12 Tracelogging Provider GUID: 82fe78cc-ff52-4e2f-a7bb-5c90636d14ba

static const GUID D3D12_MANIFEST_PROVIDER = { 0x5d8087dd, 0x3a9b, 0x4f56, { 0x90, 0xdf, 0x49, 0x19, 0x6c, 0xdc, 0x4f, 0x11 } };
static const GUID D3D12_TRACELOGGING_PROVIDER = { 0x82fe78cc, 0xff52, 0x4e2f, { 0xa7, 0xbb, 0x5c, 0x90, 0x63, 0x6d, 0x14, 0xba } };

struct CacheStats {
    ULONG NumRequiredLookups;
    ULONG NumRequiredHitsInPSDB;
    ULONG NumRequiredHitsInDynamicCache;
    ULONG NumIgnoredHits;
    ULONG NumOptionalLookups;
    ULONG NumOptionalHitsInPSDB;
    ULONG NumOptionalHitsInDynamicCache;
    ULONG NumDynamicCacheStores;
};

const size_t NUM_EVENT_TYPES = 3;
static const char* event_names[NUM_EVENT_TYPES] = { "PSOs", "state objects", "state object additions" };

// Update ProcessStats to track stats per event type
struct ProcessStats {
    // Index 0: 161 (PSOs), 1: 162 (state objects), 2: 163 (state object additions)
    size_t total_events[NUM_EVENT_TYPES] = {0, 0, 0};
    size_t hit_events[NUM_EVENT_TYPES] = {0, 0, 0};
    size_t last_printed_total_events[NUM_EVENT_TYPES] = {0, 0, 0};

    // Per-thread begin timestamps for timing begin/end event pairs
    std::unordered_map<DWORD, LONGLONG> begin_qpc[NUM_EVENT_TYPES];
    // Accumulated total time in QPC ticks
    LONGLONG total_time_qpc[NUM_EVENT_TYPES] = {};

    bool has_psdb = false;
    std::string exe_name;
};

// Per-executable stored times: [event_type] -> total ms
struct ExeTimes {
    double total_time_ms[NUM_EVENT_TYPES] = {};
    bool has_data = false;
};

// Global dictionary: exe name -> { asd_on times, asd_off times }
std::unordered_map<std::string, std::pair<ExeTimes, ExeTimes>> g_exe_times; // pair<asd_on, asd_off>

// QPC frequency for converting ETW timestamps to milliseconds
LARGE_INTEGER g_qpcFrequency;

std::unordered_map<DWORD, ProcessStats> process_stats;
std::unordered_set<DWORD> asdinit_pids;
std::mutex stats_mutex;
// Guards console writes so multi-line diagnostics from concurrent PIDs don't interleave.
std::mutex console_mutex;
std::atomic<bool> running{ true };
std::atomic<bool> g_verbose{ false };

// Retrieves the TRACE_EVENT_INFO for an event. Returns an empty vector on failure;
// on success the returned buffer owns the storage that the pointer refers to.
std::vector<BYTE> GetEventInfo(PEVENT_RECORD pEvent) {
    ULONG bufferSize = 0;
    if (TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize) != ERROR_INSUFFICIENT_BUFFER)
        return {};
    std::vector<BYTE> buffer(bufferSize);
    auto eventInfo = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
    if (TdhGetEventInformation(pEvent, 0, NULL, eventInfo, &bufferSize) != ERROR_SUCCESS)
        return {};
    return buffer;
}

std::string GetExeNameFromPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "unknown";
    char path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
        CloseHandle(hProcess);
        std::string full(path);
        auto pos = full.find_last_of("\\/");
        return pos != std::string::npos ? full.substr(pos + 1) : full;
    }
    CloseHandle(hProcess);
    return "unknown";
}

void LogProcessTimes(DWORD pid, const ProcessStats& ps) {
    std::lock_guard<std::mutex> consoleLock(console_mutex);
    const std::string& exe = ps.exe_name;
    const char* asdMode = ps.has_psdb ? "ASD ON" : "ASD OFF";

    auto& entry = g_exe_times[exe];
    auto& times = ps.has_psdb ? entry.first : entry.second;

    std::cout << "\n=== PID " << pid << " (" << exe << ", " << asdMode << ") exited ===\n";
    for (int i = 0; i < NUM_EVENT_TYPES; ++i) {
        double ms = g_qpcFrequency.QuadPart > 0 ? (double)ps.total_time_qpc[i] * 1000.0 / g_qpcFrequency.QuadPart : 0.0;
        times.total_time_ms[i] = ms;
        std::cout << "  [" << event_names[i] << "] Total time: " << std::fixed << std::setprecision(2) << ms << " ms\n";
    }
    times.has_data = true;

    // If both ASD ON and ASD OFF data exist, show comparison
    if (entry.first.has_data && entry.second.has_data) {
        std::cout << "\n--- Comparison for " << exe << " (ASD ON vs ASD OFF) ---\n";
        for (int i = 0; i < NUM_EVENT_TYPES; ++i) {
            double asd_on_ms = entry.first.total_time_ms[i];
            double asd_off_ms = entry.second.total_time_ms[i];
            if (asd_off_ms > 0.0) {
                double pct_faster = (asd_off_ms - asd_on_ms) / asd_off_ms * 100.0;
                std::cout << "  [" << event_names[i] << "] ASD ON: " << std::fixed << std::setprecision(2) << asd_on_ms
                          << " ms, ASD OFF: " << asd_off_ms << " ms, "
                          << (pct_faster >= 0 ? "faster" : "slower") << " by " << std::abs(pct_faster) << "%\n";
            } else {
                std::cout << "  [" << event_names[i] << "] ASD OFF time is 0, cannot compare\n";
            }
        }
        std::cout << std::flush;
    }
}

// Add global handles for cleanup
TRACEHANDLE g_sessionHandle = 0;
EVENT_TRACE_PROPERTIES* g_props = nullptr;
std::atomic<bool> g_stopRequested{ false };

// Print stats only if total_events for any event type changed since last print
void PrintStats() {
    std::lock_guard<std::mutex> lock(stats_mutex);
    std::lock_guard<std::mutex> consoleLock(console_mutex);
    for (auto& kv : process_stats) {
        DWORD pid = kv.first;
        ProcessStats& stats = kv.second;
        bool printed = false;
        for (int i = 0; i < NUM_EVENT_TYPES; ++i) {
            if (stats.total_events[i] != stats.last_printed_total_events[i]) {
                double hit_rate = stats.total_events[i] == 0 ? 0.0 : (double)stats.hit_events[i] / stats.total_events[i] * 100.0;
                double total_time_ms = g_qpcFrequency.QuadPart > 0 ? (double)stats.total_time_qpc[i] * 1000.0 / g_qpcFrequency.QuadPart : 0.0;
                std::cout << "PID " << pid << " [" << event_names[i] << "]: "
                    << "Total events: " << stats.total_events[i] << ", "
                    << "Hits: " << stats.hit_events[i] << ", "
                    << "Hit rate: " << std::fixed << std::setprecision(2) << hit_rate << "%, "
                    << "Total time: " << total_time_ms << " ms\n";

                stats.last_printed_total_events[i] = stats.total_events[i];
                printed = true;
            }
        }
        if (printed) std::cout << std::flush;
    }
}

void ParseManifestPayload(PEVENT_RECORD pEvent) {
    CacheStats stats = {};
    std::vector<BYTE> buffer = GetEventInfo(pEvent);
    if (buffer.empty()) return;
    auto eventInfo = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());

    // Find the fields by name
    for (ULONG i = 0; i < eventInfo->TopLevelPropertyCount; ++i) {
        PROPERTY_DATA_DESCRIPTOR propDesc = {};
        propDesc.PropertyName = (ULONGLONG)(eventInfo->EventPropertyInfoArray[i].NameOffset + (PBYTE)eventInfo);
        propDesc.ArrayIndex = ULONG_MAX;
        ULONG value = 0;
        ULONG valueSize = sizeof(value);
        ULONG status = TdhGetProperty(pEvent, 0, NULL, 1, &propDesc, valueSize, (PBYTE)&value);
        if (status != ERROR_SUCCESS) continue;

        std::wstring propName((WCHAR*)((BYTE*)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset));
        if (propName == L"NumRequiredLookups") stats.NumRequiredLookups = value;
        else if (propName == L"NumRequiredHitsInPSDB") stats.NumRequiredHitsInPSDB = value;
        else if (propName == L"NumRequiredHitsInDynamicCache") stats.NumRequiredHitsInDynamicCache = value;
        else if (propName == L"NumIgnoredHits") stats.NumIgnoredHits = value;
        else if (propName == L"NumOptionalLookups") stats.NumOptionalLookups = value;
        else if (propName == L"NumOptionalHitsInPSDB") stats.NumOptionalHitsInPSDB = value;
        else if (propName == L"NumOptionalHitsInDynamicCache") stats.NumOptionalHitsInDynamicCache = value;
        else if (propName == L"NumDynamicCacheStores") stats.NumDynamicCacheStores = value;
    }

    if (stats.NumRequiredLookups == 0)
        return;

    DWORD pid = pEvent->EventHeader.ProcessId;
    int idx = -1;
    if (pEvent->EventHeader.EventDescriptor.Id == 161) idx = 0;
    else if (pEvent->EventHeader.EventDescriptor.Id == 162) idx = 1;
    else if (pEvent->EventHeader.EventDescriptor.Id == 163) idx = 2;
    if (idx < 0) return;

    std::lock_guard<std::mutex> lock(stats_mutex);
    auto& ps = process_stats[pid];
    ps.total_events[idx]++;
    if (stats.NumRequiredLookups == stats.NumRequiredHitsInPSDB) {
        ps.hit_events[idx]++;
    }
}

enum class AsdInitStep : uint32_t
{
    None,
    Success,
    ReadApplicationRegistration,
    OpenPsdb,
    IdentityCheck
};

enum class ApplicationDescSource : uint32_t
{
    None = 0,
    PrecompiledDatabaseOverride = 1,
    SetApplicationIdentity = 2,
    ShaderCacheRegistration = 3,
};

enum class DefaultPsdbSource : uint32_t
{
    None = 0,
    PrecompiledDatabaseOverride = 1,
    PrecompiledDatabasePath = 2,
    ShaderCacheRegistration = 3,
};

LPCSTR AsdInitStepToString(AsdInitStep step)
{ 
    switch (step)
    {
    case AsdInitStep::None: return "None";
    case AsdInitStep::Success: return "Success";
    case AsdInitStep::ReadApplicationRegistration: return "ReadApplicationRegistration";
    case AsdInitStep::OpenPsdb: return "OpenPsdb";
    case AsdInitStep::IdentityCheck: return "IdentityCheck";
    };

    return "Step Unknown";
}

LPCSTR ApplicationDescSourceToString(ApplicationDescSource source)
{
    switch (source)
    {
    case ApplicationDescSource::None: return "None";
    case ApplicationDescSource::PrecompiledDatabaseOverride: return "PrecompiledDatabaseOverride";
    case ApplicationDescSource::SetApplicationIdentity: return "SetApplicationIdentity";
    case ApplicationDescSource::ShaderCacheRegistration: return "ShaderCacheRegistration";
    };

    return "Unknown";
}

LPCSTR DefaultPsdbSourceToString(DefaultPsdbSource source)
{
    switch (source)
    {
    case DefaultPsdbSource::None: return "None";
    case DefaultPsdbSource::PrecompiledDatabaseOverride: return "PrecompiledDatabaseOverride";
    case DefaultPsdbSource::PrecompiledDatabasePath: return "PrecompiledDatabasePath";
    case DefaultPsdbSource::ShaderCacheRegistration: return "ShaderCacheRegistration";
    };

    return "Unknown";
}

// A parsed TraceLogging payload. Fields are keyed by "StructName.FieldName" for members of a
// TraceLoggingStruct, or by the bare field name for top-level fields. Keying by the qualified
// name matters here: ASDInit repeats ExeFilename, EngineName, CompilerVersion and AdapterFamily
// across multiple structs.
struct TraceLoggingPayload {
    std::map<std::wstring, std::wstring> strings;
    std::map<std::wstring, uint64_t> integers;

    std::optional<std::wstring> GetString(const wchar_t* key) const {
        auto it = strings.find(key);
        if (it == strings.end()) return std::nullopt;
        return it->second;
    }
    std::optional<uint64_t> GetInt(const wchar_t* key) const {
        auto it = integers.find(key);
        if (it == integers.end()) return std::nullopt;
        return it->second;
    }
};

// Reads a single (possibly struct-nested) property into the payload maps.
// structName is null for top-level fields.
static void ReadProperty(PEVENT_RECORD pEvent, TRACE_EVENT_INFO* eventInfo,
                         const EVENT_PROPERTY_INFO& propInfo, const wchar_t* structName,
                         TraceLoggingPayload& out) {
    auto* name = (const wchar_t*)((BYTE*)eventInfo + propInfo.NameOffset);

    PROPERTY_DATA_DESCRIPTOR desc[2] = {};
    ULONG descCount = 0;
    if (structName) {
        desc[0].PropertyName = reinterpret_cast<ULONGLONG>(structName);
        desc[0].ArrayIndex = 0;
        desc[1].PropertyName = reinterpret_cast<ULONGLONG>(name);
        desc[1].ArrayIndex = ULONG_MAX;
        descCount = 2;
    } else {
        desc[0].PropertyName = reinterpret_cast<ULONGLONG>(name);
        desc[0].ArrayIndex = ULONG_MAX;
        descCount = 1;
    }

    std::wstring key;
    if (structName) {
        key = structName;
        key += L'.';
    }
    key += name;

    switch (propInfo.nonStructType.InType) {
    case TDH_INTYPE_UNICODESTRING: {
        ULONG size = 0;
        if (TdhGetPropertySize(pEvent, 0, NULL, descCount, desc, &size) != ERROR_SUCCESS || size == 0)
            return;
        std::vector<BYTE> buf(size + sizeof(wchar_t), 0);
        if (TdhGetProperty(pEvent, 0, NULL, descCount, desc, size, buf.data()) != ERROR_SUCCESS)
            return;
        out.strings[key] = std::wstring(reinterpret_cast<const wchar_t*>(buf.data()));
        break;
    }
    case TDH_INTYPE_INT8:
    case TDH_INTYPE_UINT8:
    case TDH_INTYPE_BOOLEAN: {
        uint8_t v = 0;
        if (TdhGetProperty(pEvent, 0, NULL, descCount, desc, sizeof(v), (PBYTE)&v) == ERROR_SUCCESS)
            out.integers[key] = v;
        break;
    }
    case TDH_INTYPE_INT16:
    case TDH_INTYPE_UINT16: {
        uint16_t v = 0;
        if (TdhGetProperty(pEvent, 0, NULL, descCount, desc, sizeof(v), (PBYTE)&v) == ERROR_SUCCESS)
            out.integers[key] = v;
        break;
    }
    case TDH_INTYPE_INT32:
    case TDH_INTYPE_UINT32:
    case TDH_INTYPE_HEXINT32: {
        uint32_t v = 0;
        if (TdhGetProperty(pEvent, 0, NULL, descCount, desc, sizeof(v), (PBYTE)&v) == ERROR_SUCCESS)
            out.integers[key] = v;
        break;
    }
    case TDH_INTYPE_INT64:
    case TDH_INTYPE_UINT64:
    case TDH_INTYPE_HEXINT64: {
        uint64_t v = 0;
        if (TdhGetProperty(pEvent, 0, NULL, descCount, desc, sizeof(v), (PBYTE)&v) == ERROR_SUCCESS)
            out.integers[key] = v;
        break;
    }
    default:
        break;
    }
}

// Walks a TraceLogging event payload, descending one level into TraceLoggingStructs.
bool ParseTraceLoggingPayload(PEVENT_RECORD pEvent, TraceLoggingPayload& out) {
    std::vector<BYTE> buffer = GetEventInfo(pEvent);
    if (buffer.empty()) return false;
    auto eventInfo = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());

    for (ULONG i = 0; i < eventInfo->TopLevelPropertyCount; ++i) {
        const EVENT_PROPERTY_INFO& propInfo = eventInfo->EventPropertyInfoArray[i];
        if (propInfo.Flags & PropertyStruct) {
            auto* structName = (const wchar_t*)((BYTE*)eventInfo + propInfo.NameOffset);
            ULONG start = propInfo.structType.StructStartIndex;
            ULONG count = propInfo.structType.NumOfStructMembers;
            for (ULONG j = 0; j < count; ++j) {
                ULONG memberIndex = start + j;
                if (memberIndex >= eventInfo->PropertyCount) break;
                ReadProperty(pEvent, eventInfo, eventInfo->EventPropertyInfoArray[memberIndex],
                             structName, out);
            }
        } else {
            ReadProperty(pEvent, eventInfo, propInfo, nullptr, out);
        }
    }
    return true;
}

// Version-shaped uint64s pack four 16-bit components; render them as decimal a.b.c.d.
std::string FormatVersion(uint64_t version) {
    std::ostringstream ss;
    ss << ((version >> 48) & 0xffff) << '.'
       << ((version >> 32) & 0xffff) << '.'
       << ((version >> 16) & 0xffff) << '.'
       << (version & 0xffff);
    return ss.str();
}

std::string NarrowString(const std::wstring& wide) {
    if (wide.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), result.data(), size, nullptr, nullptr);
    return result;
}

static std::string FormatStringField(const TraceLoggingPayload& payload, const wchar_t* key) {
    auto value = payload.GetString(key);
    if (!value) return "(absent)";
    return "\"" + NarrowString(*value) + "\"";
}

static std::string FormatVersionField(const TraceLoggingPayload& payload, const wchar_t* key) {
    auto value = payload.GetInt(key);
    if (!value) return "(absent)";
    return FormatVersion(*value);
}

static bool EqualsIgnoringCase(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (towlower(a[i]) != towlower(b[i])) return false;
    }
    return true;
}

// One row of the diagnostics table. An empty right value makes the row single-column; a non-empty
// note appends an inline mismatch marker.
struct DiagRow {
    std::string label;
    std::string left;
    std::string right;
    std::string note;
};

// A titled group of rows. Empty column headers make the whole section single-column.
struct DiagSection {
    std::string title;
    std::string leftHeader;
    std::string rightHeader;
    std::vector<DiagRow> rows;
};

static std::string PadTo(const std::string& s, size_t width) {
    if (s.size() >= width) return s;
    return s + std::string(width - s.size(), ' ');
}

static void Widen(size_t& width, size_t candidate) {
    if (candidate > width) width = candidate;
}

// Columns are sized to their widest content across every section, so real-world values -- full
// executable paths, long adapter family names -- stay aligned instead of pushing later columns out
// of position on whichever row happens to be longest. Widths are capped so that a single very long
// path can't stretch the whole table past a readable console width; values over the cap wrap onto a
// continuation line instead.
static const size_t kMaxColumnWidth = 60;

static void RenderSections(std::ostringstream& ss, const std::vector<DiagSection>& sections) {
    const size_t gap = 2;
    size_t labelWidth = 0;
    size_t leftWidth = 0;
    size_t rightWidth = 0;

    for (const DiagSection& section : sections) {
        // A section title occupies the label column plus the ": " separator.
        if (section.title.size() > 2) Widen(labelWidth, section.title.size() - 2);
        Widen(leftWidth, section.leftHeader.size());
        for (const DiagRow& row : section.rows) {
            Widen(labelWidth, row.label.size());
            // Only values with something after them need to be padded to a column width.
            if (!row.right.empty() || !row.note.empty()) Widen(leftWidth, row.left.size());
            if (!row.note.empty()) Widen(rightWidth, row.right.size());
        }
    }
    if (leftWidth > kMaxColumnWidth) leftWidth = kMaxColumnWidth;
    if (rightWidth > kMaxColumnWidth) rightWidth = kMaxColumnWidth;
    leftWidth += gap;
    rightWidth += gap;

    const std::string continuation(4 + labelWidth + 2, ' ');

    for (size_t i = 0; i < sections.size(); ++i) {
        const DiagSection& section = sections[i];
        if (i != 0) ss << "\n";

        if (section.leftHeader.empty()) {
            ss << "  " << section.title << "\n";
        } else {
            ss << "  " << PadTo(section.title, labelWidth + 4) << PadTo(section.leftHeader, leftWidth)
               << section.rightHeader << "\n";
        }

        for (const DiagRow& row : section.rows) {
            ss << "    " << PadTo(row.label, labelWidth) << ": ";
            if (row.right.empty() && row.note.empty()) {
                ss << row.left << "\n";
                continue;
            }

            if (row.left.size() > leftWidth - gap) {
                ss << row.left << "\n" << continuation;
            } else {
                ss << PadTo(row.left, leftWidth);
            }

            if (row.note.empty()) {
                ss << row.right << "\n";
            } else if (row.right.empty()) {
                ss << "<-- " << row.note << "\n";
            } else if (row.right.size() > rightWidth - gap) {
                ss << row.right << "\n" << continuation << "<-- " << row.note << "\n";
            } else {
                ss << PadTo(row.right, rightWidth) << "<-- " << row.note << "\n";
            }
        }
    }
}

// Returns the inline marker text for a mismatched string pair, or an empty string when the two
// agree (or either is absent). Differing only by case is a common and easily-missed registration
// bug, so it gets its own wording.
static std::string StringMismatchNote(const TraceLoggingPayload& payload, const wchar_t* keyA,
                                      const wchar_t* keyB, bool& anyMismatch) {
    auto a = payload.GetString(keyA);
    auto b = payload.GetString(keyB);
    if (!a || !b || *a == *b) return std::string();
    anyMismatch = true;
    return EqualsIgnoringCase(*a, *b) ? "mismatch (differs only by case)" : "mismatch";
}

// Prints the decoded ASDInit payload as three comparisons, which is how the identity check
// actually reasons about it: does this PSDB describe this application, can this driver consume
// what the PSDB compiler produced, and did the compiler resolve the profile the driver expects.
// Returns true if any known identity rule failed.
bool DumpAsdInitPayload(std::ostringstream& ss, const TraceLoggingPayload& payload) {
    bool anyMismatch = false;

    auto schemaVersion = payload.GetInt(L"schemaVersion");
    ss << "  --- ASDInit diagnostics (schemaVersion ";
    if (schemaVersion) ss << *schemaVersion; else ss << "unknown";
    ss << ") ---\n\n";

    DiagSection appMatch;
    appMatch.title = "Application match";
    appMatch.leftHeader = "D3D sees now";
    appMatch.rightHeader = "PSDB was built for";
    appMatch.rows.push_back({ "Name",
        FormatStringField(payload, L"ApplicationDesc.Name"),
        FormatStringField(payload, L"ApplicationIdentity.ApplicationName"),
        StringMismatchNote(payload, L"ApplicationDesc.Name",
                           L"ApplicationIdentity.ApplicationName", anyMismatch) });
    appMatch.rows.push_back({ "Engine",
        FormatStringField(payload, L"ApplicationDesc.EngineName"),
        FormatStringField(payload, L"ApplicationIdentity.EngineName"),
        StringMismatchNote(payload, L"ApplicationDesc.EngineName",
                           L"ApplicationIdentity.EngineName", anyMismatch) });
    appMatch.rows.push_back({ "Version",
        FormatVersionField(payload, L"ApplicationDesc.Version"),
        FormatVersionField(payload, L"ApplicationIdentity.ApplicationVersion"), "" });
    appMatch.rows.push_back({ "Engine version",
        FormatVersionField(payload, L"ApplicationDesc.EngineVersion"),
        FormatVersionField(payload, L"ApplicationIdentity.EngineVersion"), "" });
    appMatch.rows.push_back({ "Executable",
        FormatStringField(payload, L"ApplicationDesc.ExeFilename"),
        FormatStringField(payload, L"ApplicationIdentity.ExeFilename"), "" });

    DiagSection abi;
    abi.title = "ABI compatibility";
    abi.leftHeader = "driver";
    abi.rightHeader = "PSDB compiler";
    abi.rows.push_back({ "Adapter family",
        FormatStringField(payload, L"AbiSupport.AdapterFamily"),
        FormatStringField(payload, L"CompilerIdentity.AdapterFamily"),
        StringMismatchNote(payload, L"AbiSupport.AdapterFamily",
                           L"CompilerIdentity.AdapterFamily", anyMismatch) });
    abi.rows.push_back({ "Compiler version",
        FormatVersionField(payload, L"AbiSupport.CompilerVersion"),
        FormatVersionField(payload, L"CompilerIdentity.CompilerVersion"), "" });

    auto minAbi = payload.GetInt(L"AbiSupport.MinimumABISupportVersion");
    auto maxAbi = payload.GetInt(L"AbiSupport.MaximumABISupportVersion");
    auto abiVersion = payload.GetInt(L"CompilerIdentity.ABIVersion");
    std::string abiRange = (minAbi && maxAbi)
        ? "[" + FormatVersion(*minAbi) + ", " + FormatVersion(*maxAbi) + "]"
        : "(absent)";
    std::string abiNote;
    if (abiVersion && minAbi && maxAbi && (*abiVersion < *minAbi || *abiVersion > *maxAbi)) {
        anyMismatch = true;
        abiNote = "out of range";
    }
    abi.rows.push_back({ "ABI version", abiRange,
        FormatVersionField(payload, L"CompilerIdentity.ABIVersion"), abiNote });

    DiagSection profile;
    profile.title = "Application profile";
    auto supportProfile = payload.GetInt(L"AbiSupport.ApplicationProfileVersion");
    auto identityProfile = payload.GetInt(L"ApplicationIdentity.ApplicationProfileVersion");
    std::string profileNote;
    if (supportProfile && identityProfile && (*supportProfile >> 32) != (*identityProfile >> 32)) {
        anyMismatch = true;
        profileNote = "major version mismatch";
    }
    profile.rows.push_back({ "Driver expects",
        FormatVersionField(payload, L"AbiSupport.ApplicationProfileVersion"), "", "" });
    profile.rows.push_back({ "PSDB resolved",
        FormatVersionField(payload, L"ApplicationIdentity.ApplicationProfileVersion"), "", profileNote });

    DiagSection sources;
    sources.title = "Sources";
    auto descSource = payload.GetInt(L"ApplicationDescSource");
    auto psdbSource = payload.GetInt(L"DefaultPsdbSource");
    sources.rows.push_back({ "Application desc",
        descSource
            ? std::string(ApplicationDescSourceToString(static_cast<ApplicationDescSource>(*descSource)))
                  + " (" + std::to_string(*descSource) + ")"
            : std::string("(not present, requires schemaVersion >= 3)"), "", "" });
    sources.rows.push_back({ "Default PSDB",
        psdbSource
            ? std::string(DefaultPsdbSourceToString(static_cast<DefaultPsdbSource>(*psdbSource)))
                  + " (" + std::to_string(*psdbSource) + ")"
            : std::string("(not present, requires schemaVersion >= 3)"), "", "" });

    RenderSections(ss, { appMatch, abi, profile, sources });
    return anyMismatch;
}

// Helper to get TraceLogging event name
std::wstring GetTraceLoggingEventName(PEVENT_RECORD pEvent) {
    std::vector<BYTE> buffer = GetEventInfo(pEvent);
    if (buffer.empty()) return L"";
    auto eventInfo = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
    if (eventInfo->EventNameOffset == 0) return L"";
    return std::wstring((WCHAR*)((BYTE*)eventInfo + eventInfo->EventNameOffset));
}

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, D3D12_TRACELOGGING_PROVIDER)) {
        std::wstring eventName = GetTraceLoggingEventName(pEvent);
        if (eventName == L"ASDInit") {
            DWORD pid = pEvent->EventHeader.ProcessId;
            TraceLoggingPayload payload;
            bool parsed = ParseTraceLoggingPayload(pEvent, payload);
            auto stepValue = parsed ? payload.GetInt(L"Step") : std::nullopt;
            AsdInitStep step = stepValue ? static_cast<AsdInitStep>(*stepValue) : AsdInitStep::None;
            bool hasPsdb = stepValue.has_value() && step == AsdInitStep::Success;
            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                auto res = process_stats.emplace(pid, ProcessStats{});
                res.first->second.has_psdb = hasPsdb;
                if (res.first->second.exe_name.empty())
                    res.first->second.exe_name = GetExeNameFromPID(pid);
                asdinit_pids.insert(pid);
            }
            auto hasDefaultPsdb = hasPsdb ? "true" : "false";
            auto stepString = stepValue ? AsdInitStepToString(step) : "Error Parsing Event";

            std::ostringstream ss;
            ss << "ASDInit event seen for PID " << pid << ", HasDefaultPsdb: " << hasDefaultPsdb
               << ", Step: " << stepString << "\n";

            bool identityFailure = stepValue && step == AsdInitStep::IdentityCheck;
            if (parsed && (identityFailure || g_verbose)) {
                bool anyMismatch = DumpAsdInitPayload(ss, payload);
                if (identityFailure && !anyMismatch) {
                    ss << "\n  No mismatch detected by known rules; the runtime may enforce a "
                          "check this tool does not model.\n";
                }
                ss << "\n";
            }

            std::lock_guard<std::mutex> lock(console_mutex);
            std::cout << ss.str() << std::flush;
        }
    } else if (IsEqualGUID(pEvent->EventHeader.ProviderId, D3D12_MANIFEST_PROVIDER)) {
        DWORD pid = pEvent->EventHeader.ProcessId;
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            if (!asdinit_pids.count(pid)) return;
        }
        USHORT eid = pEvent->EventHeader.EventDescriptor.Id;
        if (eid == 161 || eid == 162 || eid == 163) {
            ParseManifestPayload(pEvent);
        }
        // Handle begin/end timing events (155/156=CreatePSO, 157/158=CreateStateObject, 159/160=AddStateObjects)
        if (eid >= 155 && eid <= 160) {
            int type_idx = (eid - 155) / 2;
            bool is_begin = (eid % 2 == 1); // 155, 157, 159 are odd (begin)
            DWORD tid = pEvent->EventHeader.ThreadId;
            LONGLONG qpc = pEvent->EventHeader.TimeStamp.QuadPart;

            std::lock_guard<std::mutex> lock(stats_mutex);
            auto& ps = process_stats[pid];
            if (is_begin) {
                ps.begin_qpc[type_idx][tid] = qpc;
            } else {
                auto it = ps.begin_qpc[type_idx].find(tid);
                if (it != ps.begin_qpc[type_idx].end()) {
                    ps.total_time_qpc[type_idx] += qpc - it->second;
                    ps.begin_qpc[type_idx].erase(it);
                }
            }
        }
    }
}

// Helper to get all running process IDs
std::unordered_set<DWORD> GetRunningPIDs() {
    std::unordered_set<DWORD> pids;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            pids.insert(pe.th32ProcessID);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pids;
}

// Helper to check if a process is still running using OpenProcess and GetExitCodeProcess
bool IsProcessAlive(DWORD pid) {
    // Try to open the process with minimal rights
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        // Could not open process, likely exited
        return false;
    }
    DWORD exitCode = 0;
    BOOL ok = GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);
    // If we can't get exit code or it's not STILL_ACTIVE, process is dead
    return ok && exitCode == STILL_ACTIVE;
}

// Thread to periodically print stats and clean up exited processes
void StatsThreadFunc() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            // Remove stats for dead processes, log their times
            for (auto it = process_stats.begin(); it != process_stats.end(); ) {
                if (!IsProcessAlive(it->first)) {
                    LogProcessTimes(it->first, it->second);
                    asdinit_pids.erase(it->first);
                    it = process_stats.erase(it);
                } else {
                    ++it;
                }
            }
        }
        PrintStats();
    }
}

// Signal handler for Ctrl+C
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        std::cout << "\nCtrl+C detected, stopping trace session...\n";
        running = false;
        g_stopRequested = true;
        // Stop the trace session
        if (g_sessionHandle && g_props) {
            ControlTraceW(g_sessionHandle, nullptr, g_props, EVENT_TRACE_CONTROL_STOP);
        }
        return TRUE;
    }
    return FALSE;
}

// Helper to stop an existing ETW session by name
void StopExistingSession(const wchar_t* sessionName) {
    // Allocate a temporary EVENT_TRACE_PROPERTIES for the control call
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!props) return;
    ZeroMemory(props, bufferSize);
    props->Wnode.BufferSize = bufferSize;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Try to stop the session; ignore errors if not running
    ULONG status = ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP);
    if (status == ERROR_SUCCESS) {
        std::wcout << L"Stopped existing ETW session: " << sessionName << L"\n";
    } else if (status != ERROR_CTX_NOT_CONSOLE && status != ERROR_WMI_INSTANCE_NOT_FOUND && status != ERROR_NOT_FOUND) {
        std::wcout << L"Attempted to stop session '" << sessionName << L"', status: " << status << L"\n";
    }
    free(props);
}

void PrintUsage(const char* exeName) {
    std::cout << "Usage: " << exeName << " [-v|--verbose] [-h|--help]\n"
              << "  -v, --verbose   Dump the full ASDInit payload for every ASDInit event,\n"
              << "                  not just when the identity check fails.\n"
              << "  -h, --help      Show this help text.\n";
}

int main(int argc, char** argv) {
    const char* exeName = (argc > 0 && argv[0]) ? argv[0] : "D3D12CacheListener";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verbose") {
            g_verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            PrintUsage(exeName);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            PrintUsage(exeName);
            return 1;
        }
    }

    TRACEHANDLE sessionHandle = 0;
    TRACEHANDLE traceHandle = 0;
    EVENT_TRACE_PROPERTIES* props = nullptr;
    const wchar_t* sessionName = L"D3D12CacheListenerSession";
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;

    // Initialize QPC frequency for timestamp-to-ms conversion
    QueryPerformanceFrequency(&g_qpcFrequency);

    // Stop any existing session with the same name before starting
    StopExistingSession(sessionName);

    props = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(props, bufferSize);
    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Set global handles for signal handler
    g_sessionHandle = sessionHandle;
    g_props = props;

    // Register Ctrl+C handler
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    ULONG status = StartTraceW(&sessionHandle, sessionName, props);
    if (status != ERROR_SUCCESS) {
        std::cerr << "StartTrace failed: " << status << "\n";
        free(props);
        return 1;
    }
    g_sessionHandle = sessionHandle; // update after StartTrace

    // Enable providers
    status = EnableTraceEx2(sessionHandle, &D3D12_MANIFEST_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "EnableTraceEx2 (manifest) failed: " << status << "\n";
    }
    status = EnableTraceEx2(sessionHandle, &D3D12_TRACELOGGING_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "EnableTraceEx2 (tracelogging) failed: " << status << "\n";
    }

    // Set up trace log
    EVENT_TRACE_LOGFILEW trace;
    ZeroMemory(&trace, sizeof(trace));
    trace.LoggerName = (LPWSTR)sessionName;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = EventRecordCallback;

    traceHandle = OpenTraceW(&trace);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "OpenTrace failed\n";
        ControlTraceW(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        return 1;
    }

    std::cout << "Listening for D3D12 ETW events. Press Ctrl+C to exit.\n";

    std::thread stats_thread(StatsThreadFunc);

    // Run ProcessTrace in a loop so we can break on Ctrl+C
    while (!g_stopRequested) {
        ULONG ptStatus = ProcessTrace(&traceHandle, 1, 0, 0);
        if (ptStatus != ERROR_SUCCESS && ptStatus != ERROR_CANCELLED) {
            std::cerr << "ProcessTrace returned error: " << ptStatus << "\n";
            break;
        }
        // If not stopped by signal, sleep briefly before retrying
        if (!g_stopRequested) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    running = false;
    stats_thread.join();

    PrintStats();

    // Ensure trace session is stopped
    ControlTraceW(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);
    free(props);
    return 0;
}