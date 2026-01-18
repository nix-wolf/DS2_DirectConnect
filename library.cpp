#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <string>
#include <fstream>
#include <iostream>
#include <map>

#pragma comment(lib, "ws2_32.lib")

// --- LINKER PROXIES (Keep your version.dll exports here) ---
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

// --- TYPES ---
typedef int (WSAAPI* tSendTo)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI* tRecvFrom)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI* tBind)(SOCKET, const struct sockaddr*, int);

tSendTo fpSendTo = NULL;
tRecvFrom fpRecvFrom = NULL;
tBind fpBind = NULL;

// --- STATE TRACKING ---
// Stores the Real NAT Port for any IP that talks to us
std::map<unsigned long, unsigned short> activeClients;

// --- CONFIGURATION READER (CACHED) ---
// Reads the file ONLY ONCE per game launch.
std::string LoadTargetIP_Ansi() {
    static std::string cachedIP = "";

    // If we already have the IP, return it immediately.
    if (!cachedIP.empty()) return cachedIP;

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
            cachedIP = line; // CACHE IT HERE

            // Log it once so we know what this instance is locked to
            std::cout << "[CONFIG] Target IP Locked: " << cachedIP << std::endl;
            return cachedIP;
        }
    }
    return "127.0.0.1";
}

// --- HOOK: bind (The Anchor) ---
// Forces the game to use Port 6500 for the Lobby so clients can find it.
int WSAAPI DetourBind(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (name->sa_family == AF_INET) {
        struct sockaddr_in* info = (struct sockaddr_in*)name;
        int originalPort = ntohs(info->sin_port);

        // If game tries to roam to random ports or DPlay ports, force 6500.
        // We only do this if it is NOT trying to bind to localhost loopback.
        if (info->sin_addr.s_addr != inet_addr("127.0.0.1")) {
            if (originalPort == 0 || (originalPort >= 2300 && originalPort <= 2400) || (originalPort >= 40000))
            {
                // std::cout << "[BIND] OVERRIDE: Port " << originalPort << " -> 6500" << std::endl;
                info->sin_port = htons(6500);
            }
        }
    }
    return fpBind(s, name, namelen);
}

// --- HOOK: recvfrom (The Listener) ---
// Learns the "Real Port" (NAT Hole) of the incoming player.
int WSAAPI DetourRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    int ret = fpRecvFrom(s, buf, len, flags, from, fromlen);

    if (ret > 0 && from && from->sa_family == AF_INET) {
        struct sockaddr_in* sender = (struct sockaddr_in*)from;

        // Save the port of any external IP (Ignore 127.0.0.1 and 10.0.0.x if you want)
        if (sender->sin_addr.s_addr != inet_addr("127.0.0.1")) {
            activeClients[sender->sin_addr.s_addr] = sender->sin_port;
        }
    }
    return ret;
}

// --- HOOK: sendto (The Smart Bridge) ---
// Redirects Broadcasts and Fixes NAT Port issues.
int WSAAPI DetourSendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    if (to->sa_family == AF_INET) {
        struct sockaddr_in* dest = (struct sockaddr_in*)to;
        struct sockaddr_in newDest = *dest;

        // 1. BROADCAST REDIRECT (Connecting to Server)
        if (dest->sin_addr.S_un.S_addr == INADDR_BROADCAST)
        {
            // Keep the port the game requested
            newDest.sin_port = dest->sin_port;

            // Use the Cached IP
            std::string ip = LoadTargetIP_Ansi();
            newDest.sin_addr.s_addr = inet_addr(ip.c_str());

            return fpSendTo(s, buf, len, flags, (struct sockaddr*)&newDest, sizeof(newDest));
        }

        // 2. NAT TRAVERSAL (Replying to Client)
        // If we know the Real Port for this IP, use it.
        if (activeClients.count(dest->sin_addr.s_addr)) {
            unsigned short realPort = activeClients[dest->sin_addr.s_addr];

            // If the game is sending to the "Wrong" port (e.g. 41010), fix it.
            if (dest->sin_port != realPort) {
                newDest.sin_port = realPort;
                return fpSendTo(s, buf, len, flags, (struct sockaddr*)&newDest, sizeof(newDest));
            }
        }
    }
    return fpSendTo(s, buf, len, flags, to, tolen);
}

void RunProcessHook() {
    // AllocConsole(); // Optional: Uncomment if you want to see the "Target IP Locked" message
    // freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

    if (MH_Initialize() != MH_OK) return;

    MH_CreateHookApi(L"ws2_32", "bind", &DetourBind, (LPVOID*)&fpBind);
    MH_CreateHookApi(L"ws2_32", "sendto", &DetourSendTo, (LPVOID*)&fpSendTo);
    MH_CreateHookApi(L"ws2_32", "recvfrom", &DetourRecvFrom, (LPVOID*)&fpRecvFrom);

    MH_EnableHook(MH_ALL_HOOKS);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        RunProcessHook();
    }
    return TRUE;
}