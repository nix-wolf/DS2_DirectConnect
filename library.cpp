
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>

#pragma comment(lib, "ws2_32.lib")
// ... (Include your standard Linker/Version.dll lines here) ...
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW")

#include "MinHook.h"

// --- DEFINITIONS ---
typedef int (WSAAPI* tSendTo)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI* tRecvFrom)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI* tBind)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI* tWSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

tSendTo fpSendTo = NULL;
tRecvFrom fpRecvFrom = NULL;
tBind fpBind = NULL;
tWSARecvFrom fpWSARecvFrom = NULL;

std::map<unsigned long, unsigned short> activeClients;

std::string LoadTargetIP_Ansi() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string fullPath = path;
    size_t lastSlash = fullPath.find_last_of("\\/");
    if (lastSlash != std::string::npos) fullPath = fullPath.substr(0, lastSlash + 1);
    fullPath += "ds2_ip.txt";
    std::ifstream infile(fullPath);
    if (infile.good()) {
        std::string line;
        std::getline(infile, line);
        if (!line.empty()) {
            if (line.back() == '\r') line.pop_back();
            return line;
        }
    }
    return "127.0.0.1";
}

// --- HOOK: bind (Logging Only) ---
int WSAAPI DetourBind(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (name->sa_family == AF_INET) {
        struct sockaddr_in* info = (struct sockaddr_in*)name;
        std::cout << "[BIND] Socket " << s << " -> Port: " << ntohs(info->sin_port) << std::endl;
    }
    return fpBind(s, name, namelen);
}

// --- HOOK: sendto (Broadcast Redirect ONLY) ---
int WSAAPI DetourSendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    if (to->sa_family == AF_INET) {
        struct sockaddr_in* dest = (struct sockaddr_in*)to;
        struct sockaddr_in newDest = *dest; // Copy original destination

        // 1. BROADCAST REDIRECT (Keep this!)
        if (dest->sin_addr.S_un.S_addr == INADDR_BROADCAST)
        {
            newDest.sin_port = dest->sin_port;
            std::string ip = LoadTargetIP_Ansi();
            newDest.sin_addr.s_addr = inet_addr(ip.c_str());
            return fpSendTo(s, buf, len, flags, (struct sockaddr*)&newDest, sizeof(newDest));
        }

        // 2. NAT TRAVERSAL (The "No Port Forwarding" Fix)
        // Check if we have a "Real Port" saved for this destination IP
        if (activeClients.count(dest->sin_addr.s_addr)) {
            unsigned short realPort = activeClients[dest->sin_addr.s_addr];

            // If the game is trying to send to the "Official" port (41010/42000),
            // override it with the "Real" NAT port (e.g., 35084).
            if (dest->sin_port != realPort) {
                // Optional Log: Verify it works
                // std::cout << "[NAT FIX] Redirecting " << ntohs(dest->sin_port) << " -> " << ntohs(realPort) << std::endl;
                newDest.sin_port = realPort;
            }
        }

        return fpSendTo(s, buf, len, flags, (struct sockaddr*)&newDest, sizeof(newDest));
    }
    return fpSendTo(s, buf, len, flags, to, tolen);
}

// --- LOGGING HELPER ---
void LogIncoming(struct sockaddr* from, int bytes) {
    if (from && from->sa_family == AF_INET) {
        struct sockaddr_in* sender = (struct sockaddr_in*)from;
        char* senderIP = inet_ntoa(sender->sin_addr);
        int senderPort = ntohs(sender->sin_port);

        if (strcmp(senderIP, "127.0.0.1") != 0) {
            std::cout << "[RECV] From " << senderIP << ":" << senderPort << " (Size: " << bytes << ")" << std::endl;
        }
    }
}

// --- HOOK: recvfrom (No Spoofing) ---
int WSAAPI DetourRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    int ret = fpRecvFrom(s, buf, len, flags, from, fromlen);

    // If we successfully received data from a real Internet IP
    if (ret > 0 && from && from->sa_family == AF_INET) {
        struct sockaddr_in* sender = (struct sockaddr_in*)from;

        // Ignore Loopback (127.0.0.1) and LAN (192.168...) to prevent confusion
        // Adjust this check if your LAN IPs are different
        if (sender->sin_addr.s_addr != inet_addr("127.0.0.1")) {

            // SAVE THE PORT!
            // "This IP is talking to me from Port X. I must reply to Port X."
            activeClients[sender->sin_addr.s_addr] = sender->sin_port;
        }
    }
    return ret;
}

// --- HOOK: WSARecvFrom (No Spoofing) ---
int WSAAPI DetourWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    int ret = fpWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    if (ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        LogIncoming(lpFrom, *lpNumberOfBytesRecvd);
    }
    return ret;
}

void RunProcessHook() {
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    std::cout << "=== DS2 RAW PASSTHROUGH MODE ===" << std::endl;

    if (MH_Initialize() != MH_OK) return;

    MH_CreateHookApi(L"ws2_32", "bind", &DetourBind, (LPVOID*)&fpBind);
    MH_CreateHookApi(L"ws2_32", "sendto", &DetourSendTo, (LPVOID*)&fpSendTo);
    MH_CreateHookApi(L"ws2_32", "recvfrom", &DetourRecvFrom, (LPVOID*)&fpRecvFrom);
    MH_CreateHookApi(L"ws2_32", "WSARecvFrom", &DetourWSARecvFrom, (LPVOID*)&fpWSARecvFrom);

    MH_EnableHook(MH_ALL_HOOKS);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        RunProcessHook();
        break;
    case DLL_PROCESS_DETACH:
        MH_Uninitialize();
        break;
    }
    return TRUE;
}