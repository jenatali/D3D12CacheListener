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

// Update ProcessStats to track stats per event type
struct ProcessStats {
    // Index 0: 161 (PSOs), 1: 162 (state objects), 2: 163 (state object additions)
    size_t total_events[NUM_EVENT_TYPES] = {0, 0, 0};
    size_t hit_events[NUM_EVENT_TYPES] = {0, 0, 0};
    size_t last_printed_total_events[NUM_EVENT_TYPES] = {0, 0, 0};
};

std::unordered_map<DWORD, ProcessStats> process_stats;
std::unordered_set<DWORD> asdinit_pids;
std::mutex stats_mutex;
std::atomic<bool> running{ true };

// Add global handles for cleanup
TRACEHANDLE g_sessionHandle = 0;
EVENT_TRACE_PROPERTIES* g_props = nullptr;
std::atomic<bool> g_stopRequested{ false };

// Print stats only if total_events for any event type changed since last print
void PrintStats() {
    static const char* event_names[NUM_EVENT_TYPES] = { "PSOs", "state objects", "state object additions" };
    std::lock_guard<std::mutex> lock(stats_mutex);
    for (auto& kv : process_stats) {
        DWORD pid = kv.first;
        ProcessStats& stats = kv.second;
        bool printed = false;
        for (int i = 0; i < NUM_EVENT_TYPES; ++i) {
            if (stats.total_events[i] != stats.last_printed_total_events[i]) {
                double hit_rate = stats.total_events[i] == 0 ? 0.0 : (double)stats.hit_events[i] / stats.total_events[i] * 100.0;
                std::cout << "PID " << pid << " [" << event_names[i] << "]: "
                    << "Total events: " << stats.total_events[i] << ", "
                    << "Hits: " << stats.hit_events[i] << ", "
                    << "Hit rate: " << std::fixed << std::setprecision(2) << hit_rate << "%\n";
                stats.last_printed_total_events[i] = stats.total_events[i];
                printed = true;
            }
        }
        if (printed) std::cout << std::flush;
    }
}

void ParseManifestPayload(PEVENT_RECORD pEvent) {
    CacheStats stats = {};
    ULONG status = ERROR_SUCCESS;
    ULONG bufferSize = 0;
    status = TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER) return;

    std::vector<BYTE> buffer(bufferSize);
    auto eventInfo = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
    status = TdhGetEventInformation(pEvent, 0, NULL, eventInfo, &bufferSize);
    if (status != ERROR_SUCCESS) return;

    // Find the fields by name
    for (ULONG i = 0; i < eventInfo->TopLevelPropertyCount; ++i) {
        PROPERTY_DATA_DESCRIPTOR propDesc = {};
        propDesc.PropertyName = (ULONGLONG)(eventInfo->EventPropertyInfoArray[i].NameOffset + (PBYTE)eventInfo);
        propDesc.ArrayIndex = ULONG_MAX;
        ULONG value = 0;
        ULONG valueSize = sizeof(value);
        status = TdhGetProperty(pEvent, 0, NULL, 1, &propDesc, valueSize, (PBYTE)&value);
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

// Helper to get TraceLogging event name
std::wstring GetTraceLoggingEventName(PEVENT_RECORD pEvent) {
    ULONG bufferSize = 0;
    ULONG status = TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER) return L"";
    std::vector<BYTE> buffer(bufferSize);
    auto eventInfo = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
    status = TdhGetEventInformation(pEvent, 0, NULL, eventInfo, &bufferSize);
    if (status != ERROR_SUCCESS) return L"";
    if (eventInfo->EventNameOffset == 0) return L"";
    return std::wstring((WCHAR*)((BYTE*)eventInfo + eventInfo->EventNameOffset));
}

void WINAPI EventRecordCallback(PEVENT_RECORD pEvent) {
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, D3D12_TRACELOGGING_PROVIDER)) {
        std::wstring eventName = GetTraceLoggingEventName(pEvent);
        if (eventName == L"ASDInit") {
            DWORD pid = pEvent->EventHeader.ProcessId;
            {
                std::lock_guard<std::mutex> lock(stats_mutex);
                process_stats.emplace(pid, ProcessStats{});
                asdinit_pids.insert(pid);
            }
            std::cout << "ASDInit event seen for PID " << pid << "\n";
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
            // Remove stats for dead processes
            for (auto it = process_stats.begin(); it != process_stats.end(); ) {
                if (!IsProcessAlive(it->first)) {
                    std::cout << "Process " << it->first << " exited, removing stats.\n";
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

int main() {
    TRACEHANDLE sessionHandle = 0;
    TRACEHANDLE traceHandle = 0;
    EVENT_TRACE_PROPERTIES* props = nullptr;
    const wchar_t* sessionName = L"D3D12CacheListenerSession";
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;

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