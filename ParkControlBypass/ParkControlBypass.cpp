#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include "MinHook/MinHook.h"

#pragma comment(lib, "Psapi.lib")

/*
To find this pattern:
1. Launch IDA 64bit.
2. Load in ParkControl.exe
3. Press ALT + T
4. In the search box, enter: %s%s&item_id=%d&license=%s
5. Use SigMakerEx plugin to generate the pattern for the function
6. Convert it from IDA style to code style
7. Adjust the mask of the signature
*/

namespace {
    const uint8_t k_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x20, 0x44 };
    const uint8_t k_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // No wildcards
    const size_t k_pattern_size = sizeof(k_pattern);

    // Function pointer type for sub_140004B80 (process_license)
    using process_license_t = uint8_t(*)(int64_t request_context,
        int64_t license_key,
        char is_activation,
        int64_t* output_license);
    process_license_t original_process_license = nullptr;

    // Global variables for thread management
    HANDLE g_main_thread = nullptr;
    HMODULE g_hmodule = nullptr;
    volatile bool g_running = true;
}

// Hooked version of process_license
uint8_t hooked_process_license(int64_t request_context,
    int64_t license_key,
    char is_activation,
    int64_t* output_license)
{
    // Force success return value
    return 1;
}

// Function to search for a byte pattern with a mask
void* find_pattern(HMODULE module,
    const uint8_t* pattern,
    const uint8_t* mask,
    size_t pattern_size)
{
    MODULEINFO module_info;
    if (!GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(module_info))) {
        return nullptr;
    }

    uint8_t* start_address = static_cast<uint8_t*>(module_info.lpBaseOfDll);
    size_t size = module_info.SizeOfImage;

    for (size_t i = 0; i < size - pattern_size; ++i) {
        bool found = true;

        for (size_t j = 0; j < pattern_size; ++j) {
            if (mask[j] != 0xFF && pattern[j] != start_address[i + j]) {
                found = false;
                break;
            }
        }

        if (found) {
            return start_address + i;
        }
    }

    return nullptr;
}

bool initialize_hook() {
    // Initialize MinHook
    if (MH_Initialize() != MH_OK) {
        return false;
    }

    // Get the base address of ParkControl.exe
    HMODULE module = GetModuleHandle(nullptr);
    if (!module) {
        return false;
    }

    // Find the function address
    void* target_function = find_pattern(module, k_pattern, k_mask, k_pattern_size);
    if (!target_function) {
        return false; // Pattern not found
    }

    // Create and enable the hook
    if (MH_CreateHook(target_function,
        &hooked_process_license,
        reinterpret_cast<LPVOID*>(&original_process_license)) != MH_OK)
    {
        return false;
    }

    if (MH_EnableHook(target_function) != MH_OK) {
        return false;
    }

    return true;
}

void cleanup_hook() {
    // Disable the hook
    void* target_function = find_pattern(GetModuleHandle(nullptr), k_pattern, k_mask, k_pattern_size);
    if (target_function) {
        MH_DisableHook(target_function);
    }

    MH_Uninitialize();
}

DWORD WINAPI main_thread(LPVOID) {
    // Initialize the hook
    if (!initialize_hook()) {
        FreeLibraryAndExitThread(g_hmodule, 1);
        return 1;
    }

    // Keep the DLL running until END key is pressed
    while (g_running) {
        if (GetAsyncKeyState(VK_END) & 0x8000) {
            g_running = false;
        }
        Sleep(75); // Small delay to avoid high CPU usage
    }

    // Cleanup hooks before unloading
    cleanup_hook();

    // Unload the DLL
    FreeLibraryAndExitThread(g_hmodule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module,
    DWORD reason_for_call,
    LPVOID reserved)
{
    switch (reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hmodule = module;
        DisableThreadLibraryCalls(module);

        // Create main thread to keep DLL running
        g_main_thread = CreateThread(nullptr, 0, main_thread, nullptr, 0, nullptr);
        if (!g_main_thread) {
            return FALSE;
        }

        break;
    case DLL_PROCESS_DETACH:
        // Signal the main thread to exit
        g_running = false;

        // Wait for the main thread to finish
        if (g_main_thread) {
            WaitForSingleObject(g_main_thread, 1000);
            CloseHandle(g_main_thread);
        }

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
