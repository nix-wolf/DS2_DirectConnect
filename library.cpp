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
typedef int (WSAAPI* tSendTo)(SOCKET, const char*, int, int, const sockaddr*, int);
typedef int (WSAAPI* tRecvFrom)(SOCKET, char*, int, int, sockaddr*, int*);
typedef int (WSAAPI* tBind)(SOCKET, const sockaddr*, int);
typedef int (WSAAPI* tWSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

tSendTo fpSendTo = nullptr;
tRecvFrom fpRecvFrom = nullptr;
tBind fpBind = nullptr;
tWSARecvFrom fpWSARecvFrom = nullptr;

std::map<unsigned long, unsigned short> activeClients;

unsigned short g_LastKnownPort = 0;
unsigned long g_TargetIPAddr = 0;

bool IsGamePort(unsigned short port) {
    int p = ntohs(port);
    // DirectPlay Default
    if (port == 6073) return true;
    // Dungeon Siege Lobby
    if (port == 6500) return true;
    // DirectPlay Legacy Range (2300-2400)
    if (port >= 2300 && port <= 2400) return true;
    // Dungeon Siege 2 Game Range (41000 - 42000)
    if (port >= 41000 && port <= 43000) return true;

    return false;
}

std::string LoadTargetIP_Ansi() {
    static std::string cachedIP = "";
    if (!cachedIP.empty()) return cachedIP;

    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
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
            cachedIP = line;

            g_TargetIPAddr = inet_addr(line.c_str());
            std::cout << "[CONFIG] Locked Target: " << cachedIP << std::endl;
            return cachedIP;
        }
    }
    return "127.0.0.1";
}

int WSAAPI DetourBind(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (name->sa_family == AF_INET) {
        sockaddr_in* info = (sockaddr_in*)name;
        std::cout << "[BIND] Socket " << s << " -> Port: " << ntohs(info->sin_port) << std::endl;
    }
    return fpBind(s, name, namelen);
}

int WSAAPI DetourSendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    if (to->sa_family == AF_INET) {
        sockaddr_in* dest = (sockaddr_in*)to;
        sockaddr_in newDest = *dest;
        bool modified = false;

        if (dest->sin_addr.S_un.S_addr == INADDR_BROADCAST)
        {
            newDest.sin_port = dest->sin_port;
            std::string ip = LoadTargetIP_Ansi();
            newDest.sin_addr.s_addr = inet_addr(ip.c_str());
            modified = true;

            static DWORD lastLog = 0;
            if (GetTickCount() - lastLog > 500) {
                std::cout << "[SEND] Broadcast Redirect -> " << ip << std::endl;
                lastLog = GetTickCount();
            }
        } else if (dest->sin_addr.s_addr == g_TargetIPAddr) {
            if (IsGamePort(dest->sin_port)) {
                // DO NOTHING. Pass through.
            } else if (g_LastKnownPort != 0 && dest->sin_port != g_LastKnownPort) {
                newDest.sin_port = g_LastKnownPort;
                modified = true;
                std::cout << "[NAT] Redirecting Reply -> Port " << ntohs(g_LastKnownPort) << std::endl;
            }
        }

        // char* destIP = inet_ntoa(dest->sin_addr);
        // if (strcmp(destIP, "127.0.0.1") != 0) {
            // std::cout << "[SEND] Direct -> " << destIP << ":" << ntohs(dest->sin_port) << " (Size: " << len << ")" << std::endl;
        // }

        if (modified) {
            return fpSendTo(s, buf, len, flags, (sockaddr*)&newDest, sizeof(newDest));
        }
    }
    return fpSendTo(s, buf, len, flags, to, tolen);
}

void CheckAndSavePort(sockaddr* from, int bytes) {
    if (from && from->sa_family == AF_INET) {
        sockaddr_in* sender = (struct sockaddr_in*)from;

        if (sender->sin_addr.s_addr != inet_addr("127.0.0.1")) {
            std::cout << "[RECV] From " << inet_ntoa(sender->sin_addr) << ":" << ntohs(sender->sin_port) << " (Size: " << bytes << ")" << std::endl;

            if (IsGamePort(sender->sin_port)) {
                if (!IsGamePort(g_LastKnownPort) && g_LastKnownPort != 0) {
                    g_LastKnownPort = 0;
                    std::cout << "   >>> [NAT] Resetting Lock (Game Port Detected) <<<" << std::endl;
                }
                return;
            }

            if (sender->sin_port != g_LastKnownPort) {
                g_LastKnownPort = sender->sin_port;
                std::cout << "   >>> [NAT] LOCKED NEW PORT: " << ntohs(g_LastKnownPort) << " <<<" << std::endl;
            }
        }
    }
}

int WSAAPI DetourRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    int ret = fpRecvFrom(s, buf, len, flags, from, fromlen);
    if (ret > 0) CheckAndSavePort(from, ret);
    return ret;
}

int WSAAPI DetourWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    int ret = fpWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    if (ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        CheckAndSavePort(lpFrom, *lpNumberOfBytesRecvd);
    }
    return ret;
}

void RunProcessHook() {
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    std::cout << "=== DS2_DIRECT_CONNECT HACK ===" << std::endl;

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