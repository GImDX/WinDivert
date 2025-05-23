/*
 * flowtrack.c
 * (C) 2019, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * DESCRIPTION:
 *
 * usage: flowtrack.exe [filter]
 */

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../../include/windivert.h"

#define MAX_FLOWS           256
#define INET6_ADDRSTRLEN    45

#define MAX_DISPLAY_LEN 30

/*
 * Flow tracking.
 */
typedef struct FLOW
{
    WINDIVERT_ADDRESS addr;
    struct FLOW *next;
} FLOW, *PFLOW;

// static HANDLE lock;
static PFLOW flows = NULL;


int __cdecl main(int argc, char **argv)
{
    HANDLE handle, thread, process, console = GetStdHandle(STD_OUTPUT_HANDLE);
    INT16 priority = 776;       // Arbitrary.
    const char *filter = "true", *err_str;
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PFLOW flow, prev;

    SYSTEMTIME st;
    time_t rawtime;
    struct tm *timeinfo;
    char time_str[32];

    DWORD path_len;
    char path[MAX_PATH+1];
    char filename[MAX_DISPLAY_LEN];

    char addr_str[INET6_ADDRSTRLEN+1];

    switch (argc)
    {
        case 1:
            break;
        case 2:
            filter = argv[1];
            break;
        default:
            fprintf(stderr, "usage: %s [filter]\n", argv[0]);
            exit(EXIT_FAILURE);
    }

    // Open WinDivert FLOW handle:
    handle = WinDivertOpen(filter, WINDIVERT_LAYER_FLOW, priority, 
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_FLOW,
                NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        return EXIT_FAILURE;
    }

    // header
    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("%-24s%-12s%-10s%-10s%-10s%-31s%-9s%-52s%-52s\n",
            "Timestamp", "Event", "Endpoint", "Parent", "PID", "Program", "Protocol", "Local", "Remote");

    // Main loop:
    while (TRUE)
    {
        if (!WinDivertRecv(handle, NULL, 0, NULL, &addr))
        {
            fprintf(stderr, "failed to read packet (%d)\n", GetLastError());
            continue;
        }

        switch (addr.Event)
        {
            case WINDIVERT_EVENT_FLOW_ESTABLISHED:

                // Flow established:
                flow = (PFLOW)malloc(sizeof(FLOW));
                if (flow == NULL)
                {
                    fprintf(stderr, "error: failed to allocate memory\n");
                    exit(EXIT_FAILURE);
                }
                memcpy(&flow->addr, &addr, sizeof(flow->addr));
                // WaitForSingleObject(lock, INFINITE);
                flow->next = flows;
                flows = flow;
                // ReleaseMutex(lock);
                break;

            case WINDIVERT_EVENT_FLOW_DELETED:

                // Flow deleted:
                prev = NULL;
                // WaitForSingleObject(lock, INFINITE);
                flow = flows;
                while (flow != NULL)
                {
                    if (memcmp(&addr.Flow, &flow->addr.Flow,
                            sizeof(addr.Flow)) == 0)
                    {
                        if (prev != NULL)
                        {
                            prev->next = flow->next;
                        }
                        else
                        {
                            flows = flow->next;
                        }
                        break;
                    }
                    prev = flow;
                    flow = flow->next;
                }
                // ReleaseMutex(lock);
                free(flow);
        }

        // Print
        if (addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED || addr.Event == WINDIVERT_EVENT_FLOW_DELETED)
        {
            GetLocalTime(&st);
            snprintf(time_str, sizeof(time_str),
            "%04d-%02d-%02d %02d:%02d:%02d.%03d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);


            // Timestamp
            printf("%-24s", time_str);

            // Event
            SetConsoleTextAttribute(console, addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED ? FOREGROUND_GREEN : FOREGROUND_RED);
            printf("%-12s", addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED ? "ESTABLISHED" : "DELETED");

            // EndpointId
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("%-10d", addr.Flow.EndpointId);

            // ParentEndpointId
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("%-10d", addr.Flow.ParentEndpointId);
            
            // PID
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("%-10d", addr.Flow.ProcessId);
            
            // Process
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, addr.Flow.ProcessId);
            path_len = 0;
            if (process != NULL)
            {
                path_len = GetProcessImageFileName(process, path, sizeof(path));
                CloseHandle(process);
            }

            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
            if (path_len != 0)
            {
                if (path_len > MAX_DISPLAY_LEN) {
                    snprintf(filename, sizeof(filename), "...%s", path + (path_len - MAX_DISPLAY_LEN + 4)); // EXTRA "...", '\0'
                } else {
                    snprintf(filename, sizeof(filename), "%s", path);  // 原始路径不足30字符则原样返回
                }
                    printf("%-31s", filename);
            }
            else if (addr.Flow.ProcessId == 4)
            {
                printf("%-31s", "Windows");
            }
            else
            {
                printf("%-31s", "Unknown");
            }

            // Protocol
            switch (addr.Flow.Protocol)
            {
                case IPPROTO_TCP:
                    SetConsoleTextAttribute(console, FOREGROUND_GREEN);
                    printf("%-9s", "TCP");
                    break;
                case IPPROTO_UDP:
                    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
                    printf("%-9s", "UDP");
                    break;
                case IPPROTO_ICMP:
                    SetConsoleTextAttribute(console, FOREGROUND_RED);
                    printf("%-9s", "ICMP");
                    break;
                case IPPROTO_ICMPV6:
                    SetConsoleTextAttribute(console, FOREGROUND_RED);
                    printf("%-9s", "ICMPV6");
                    break;
                default:
                    SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
                    printf("%-9u", addr.Flow.Protocol);
                    break;
            }

            // Address
            SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            WinDivertHelperFormatIPv6Address(addr.Flow.LocalAddr, addr_str, sizeof(addr_str));
            printf("%-39s:%5u %s ", addr_str, addr.Flow.LocalPort,
                (addr.Outbound ? "---->" : "<----"));
            WinDivertHelperFormatIPv6Address(addr.Flow.RemoteAddr, addr_str, sizeof(addr_str));
            printf("%-39s:%5u\n", addr_str, addr.Flow.RemotePort);
        }
    }

    return 0;
}
