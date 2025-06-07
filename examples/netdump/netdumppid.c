/*
 * netdump.c
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
 * This is a simple traffic monitor.  It uses a WinDivert handle in SNIFF mode.
 * The SNIFF mode copies packets and does not block the original.
 *
 * usage: netdump.exe windivert-filter [priority]
 *
 */
#include <winsock2.h>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ws2tcpip.h>
#include <psapi.h>
#include <iphlpapi.h>

#include <shlwapi.h> 

#include <windivert.h>
#include <uthash.h>

#define ntohs(x)            WinDivertHelperNtohs(x)
#define ntohl(x)            WinDivertHelperNtohl(x)

#define MAXBUF              WINDIVERT_MTU_MAX

#define HEXDUMP_COL         32

typedef struct {
    int family;
    BOOL tcp;
    UINT8 local_addr[16];
    UINT8 remote_addr[16];
    USHORT local_port;
    USHORT remote_port;
} ConnKey;

typedef struct {
    ConnKey key;     // 必须在最前，供 HASH_ADD_KEYPTR 使用
    DWORD pid;
    time_t timestamp;  // 用于清理时判断生存时间
    UT_hash_handle hh;
} ConnCacheEntry;
ConnCacheEntry* conn_cache = NULL;

BOOL ConnExistsInSystemTable(const ConnKey* key, DWORD* out_pid)
{
    DWORD size = 0;
    void* table = NULL;
    DWORD pid = 0;
    BOOL found = FALSE;

    DWORD table_class = key->tcp ? TCP_TABLE_OWNER_PID_ALL : UDP_TABLE_OWNER_PID;
    int family = key->family;

    if (key->tcp)
        GetExtendedTcpTable(NULL, &size, FALSE, family, table_class, 0);
    else
        GetExtendedUdpTable(NULL, &size, FALSE, family, table_class, 0);

    table = malloc(size);
    if (!table) return FALSE;

    DWORD result = key->tcp ?
        GetExtendedTcpTable(table, &size, FALSE, family, table_class, 0) :
        GetExtendedUdpTable(table, &size, FALSE, family, table_class, 0);

    if (result != NO_ERROR)
    {
        free(table);
        return FALSE;
    }

    if (family == AF_INET)
    {
        if (key->tcp)
        {
            PMIB_TCPTABLE_OWNER_PID p = (PMIB_TCPTABLE_OWNER_PID)table;
            for (DWORD i = 0; i < p->dwNumEntries; i++)
            {
                if (p->table[i].dwLocalAddr == *(DWORD*)key->local_addr &&
                    p->table[i].dwRemoteAddr == *(DWORD*)key->remote_addr &&
                    ntohs((USHORT)p->table[i].dwLocalPort) == key->local_port &&
                    ntohs((USHORT)p->table[i].dwRemotePort) == key->remote_port)
                {
                    pid = p->table[i].dwOwningPid;
                    found = TRUE;
                    break;
                }
            }
        }
        else
        {
            PMIB_UDPTABLE_OWNER_PID p = (PMIB_UDPTABLE_OWNER_PID)table;
            for (DWORD i = 0; i < p->dwNumEntries; i++)
            {
                DWORD local_ip = p->table[i].dwLocalAddr;
                USHORT local_port = ntohs((USHORT)p->table[i].dwLocalPort);
                if ((local_ip == *(DWORD*)key->local_addr || local_ip == 0) &&
                    local_port == key->local_port)
                {
                    pid = p->table[i].dwOwningPid;
                    found = TRUE;
                    break;
                }
            }
        }
    }
    else
    {
        if (key->tcp)
        {
            PMIB_TCP6TABLE_OWNER_PID p = (PMIB_TCP6TABLE_OWNER_PID)table;
            for (DWORD i = 0; i < p->dwNumEntries; i++)
            {
                if (memcmp(p->table[i].ucLocalAddr, key->local_addr, 16) == 0 &&
                    memcmp(p->table[i].ucRemoteAddr, key->remote_addr, 16) == 0 &&
                    ntohs((USHORT)p->table[i].dwLocalPort) == key->local_port &&
                    ntohs((USHORT)p->table[i].dwRemotePort) == key->remote_port)
                {
                    pid = p->table[i].dwOwningPid;
                    found = TRUE;
                    break;
                }
            }
        }
        else
        {
            PMIB_UDP6TABLE_OWNER_PID p = (PMIB_UDP6TABLE_OWNER_PID)table;
            for (DWORD i = 0; i < p->dwNumEntries; i++)
            {
                USHORT local_port = ntohs((USHORT)p->table[i].dwLocalPort);
                if ((memcmp(p->table[i].ucLocalAddr, key->local_addr, 16) == 0 ||
                     memcmp(p->table[i].ucLocalAddr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0) &&
                    local_port == key->local_port)
                {
                    pid = p->table[i].dwOwningPid;
                    found = TRUE;
                    break;
                }
            }
        }
    }

    // debug print
    // if (pid == 0) 
    // {
    //     if (key->family == AF_INET)
    //     {
    //         if (key->tcp)
    //         {
    //             PMIB_TCPTABLE_OWNER_PID p = (PMIB_TCPTABLE_OWNER_PID)table;
    //             for (DWORD i = 0; i < p->dwNumEntries; i++)
    //             {
    //                 DWORD lip = p->table[i].dwLocalAddr;
    //                 DWORD rip = p->table[i].dwRemoteAddr;
    //                 USHORT lp = ntohs((USHORT)p->table[i].dwLocalPort);
    //                 USHORT rp = ntohs((USHORT)p->table[i].dwRemotePort);
    //                 char local_str[INET_ADDRSTRLEN], remote_str[INET_ADDRSTRLEN];
    //                 inet_ntop(AF_INET, &lip, local_str, sizeof(local_str));
    //                 inet_ntop(AF_INET, &rip, remote_str, sizeof(remote_str));
    //                 printf("[DEBUG] IPv4 tcp: local=%s:%u, remote=%s:%u\n", local_str, lp, remote_str, rp);
    //             }
    //         }
    //         else
    //         {
    //             PMIB_UDPTABLE_OWNER_PID p = (PMIB_UDPTABLE_OWNER_PID)table;
    //             for (DWORD i = 0; i < p->dwNumEntries; i++)
    //             {
    //                 DWORD lip = p->table[i].dwLocalAddr;
    //                 USHORT lp = ntohs((USHORT)p->table[i].dwLocalPort);
    //                 char local_str[INET_ADDRSTRLEN];
    //                 inet_ntop(AF_INET, &lip, local_str, sizeof(local_str));
    //                 printf("[DEBUG] IPv4 udp: local=%s:%u\n", local_str, lp);
    //             }
    //         }
    //     }
    //     else if (key->family == AF_INET6)
    //     {
    //         if (key->tcp)
    //         {
    //             PMIB_TCP6TABLE_OWNER_PID p = (PMIB_TCP6TABLE_OWNER_PID)table;
    //             for (DWORD i = 0; i < p->dwNumEntries; i++)
    //             {
    //                 USHORT lp = ntohs((USHORT)p->table[i].dwLocalPort);
    //                 USHORT rp = ntohs((USHORT)p->table[i].dwRemotePort);
    //                 struct in6_addr la, ra;
    //                 char local_str[INET6_ADDRSTRLEN], remote_str[INET6_ADDRSTRLEN];
    //                 memcpy(&la, p->table[i].ucLocalAddr, 16);
    //                 memcpy(&ra, p->table[i].ucRemoteAddr, 16);
    //                 inet_ntop(AF_INET6, &la, local_str, sizeof(local_str));
    //                 inet_ntop(AF_INET6, &ra, remote_str, sizeof(remote_str));
    //                 printf("[DEBUG] IPv6 tcp: local=%s:%u, remote=%s:%u\n", local_str, lp, remote_str, rp);
    //             }
    //         }
    //         else
    //         {
    //             PMIB_UDP6TABLE_OWNER_PID p = (PMIB_UDP6TABLE_OWNER_PID)table;
    //             for (DWORD i = 0; i < p->dwNumEntries; i++)
    //             {
    //                 USHORT lp = ntohs((USHORT)p->table[i].dwLocalPort);
    //                 struct in6_addr la;
    //                 char local_str[INET6_ADDRSTRLEN];
    //                 memcpy(&la, p->table[i].ucLocalAddr, 16);
    //                 inet_ntop(AF_INET6, &la, local_str, sizeof(local_str));
    //                 printf("[DEBUG] IPv6 udp: local=%s:%u\n", local_str, lp);
    //             }
    //         }
    //     }
    // }

    free(table);
    if (found && out_pid)
        *out_pid = pid;
    return found;
}

#define EXPIRE_SECONDS         30       // 缓存项最大保留时间
#define CACHE_CLEAN_INTERVAL    1       // 清理间隔（秒）
CRITICAL_SECTION cache_lock;
DWORD WINAPI CleanupCacheThread(LPVOID lpParam)
{
    while (1)
    {
        Sleep(5000);
        time_t now = time(NULL);

        EnterCriticalSection(&cache_lock);

        ConnCacheEntry *entry, *tmp;
        HASH_ITER(hh, conn_cache, entry, tmp)
        {
            if (now - entry->timestamp < EXPIRE_SECONDS)
                continue;

            DWORD dummy_pid = 0;
            if (!ConnExistsInSystemTable(&entry->key, &dummy_pid))
            {
                char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
                const char* proto_str = entry->key.tcp ? "TCP" : "UDP";
                unsigned int count = HASH_COUNT(conn_cache);

                if (entry->key.family == AF_INET)
                {
                    inet_ntop(AF_INET, entry->key.local_addr, src_str, sizeof(src_str));
                    inet_ntop(AF_INET, entry->key.remote_addr, dst_str, sizeof(dst_str));
                    printf("\nKEY_CLEAN HASH_COUNT=%u [IPv4 %s: local=%s:%u, remote=%s:%u, pid=%u]\n",
                        count, proto_str, src_str, entry->key.local_port, dst_str, entry->key.remote_port, entry->pid);
                }
                else if (entry->key.family == AF_INET6)
                {
                    inet_ntop(AF_INET6, entry->key.local_addr, src_str, sizeof(src_str));
                    inet_ntop(AF_INET6, entry->key.remote_addr, dst_str, sizeof(dst_str));
                    printf("\nKEY_CLEAN HASH_COUNT=%u [IPv6 %s: local=%s:%u, remote=%s:%u, pid=%u]\n",
                        count, proto_str, src_str, entry->key.local_port, dst_str, entry->key.remote_port, entry->pid);
                }
                HASH_DEL(conn_cache, entry);
                free(entry);
            }
        }

        LeaveCriticalSection(&cache_lock);
    }

    return 0;
}

DWORD FindProcessIdByTcpOrUdp(
    PWINDIVERT_IPHDR ip_header,
    PWINDIVERT_IPV6HDR ipv6_header,
    PWINDIVERT_TCPHDR tcp_header,
    PWINDIVERT_UDPHDR udp_header,
    WINDIVERT_ADDRESS* addr)
{
    DWORD pid = 0;
    BOOL is_tcp = (tcp_header != NULL);
    if (!is_tcp && udp_header == NULL) return 0;

    int family = ipv6_header ? AF_INET6 : AF_INET;
    BOOL outbound = addr && addr->Outbound;
    USHORT src_port = is_tcp ? ntohs(tcp_header->SrcPort) : ntohs(udp_header->SrcPort);
    USHORT dst_port = is_tcp ? ntohs(tcp_header->DstPort) : ntohs(udp_header->DstPort);
    UINT8 local_addr[16] = {0}, remote_addr[16] = {0};

    if (family == AF_INET)
    {
        DWORD src_ip = ip_header->SrcAddr;
        DWORD dst_ip = ip_header->DstAddr;
        memcpy(local_addr, outbound ? &src_ip : &dst_ip, 4);
        memcpy(remote_addr, outbound ? &dst_ip : &src_ip, 4);
    }
    else
    {
        memcpy(local_addr, outbound ? ipv6_header->SrcAddr : ipv6_header->DstAddr, 16);
        memcpy(remote_addr, outbound ? ipv6_header->DstAddr : ipv6_header->SrcAddr, 16);
    }

    USHORT local_port = outbound ? src_port : dst_port;
    USHORT remote_port = outbound ? dst_port : src_port;

    // 缓存查找
    ConnKey lookup_key = {0};
    lookup_key.family = family;
    lookup_key.tcp = is_tcp;
    memcpy(lookup_key.local_addr, local_addr, (family == AF_INET ? 4 : 16));
    memcpy(lookup_key.remote_addr, remote_addr, (family == AF_INET ? 4 : 16));
    lookup_key.local_port = local_port;
    lookup_key.remote_port = remote_port;

    ConnCacheEntry* entry = NULL;
    HASH_FIND(hh, conn_cache, &lookup_key, sizeof(ConnKey), entry);
    if (entry){
        // printf("KEY_FOUND\n");
        return entry->pid;
    } 

    // 查询系统连接表
    if (ConnExistsInSystemTable(&lookup_key, &pid) && pid != 0) {

        // 缓存插入
        ConnCacheEntry* new_entry = malloc(sizeof(ConnCacheEntry));
        if (new_entry) {
            memset(new_entry, 0, sizeof(*new_entry));
            memcpy(&new_entry->key, &lookup_key, sizeof(ConnKey));
            new_entry->pid = pid;
            new_entry->timestamp = time(NULL);
            HASH_ADD_KEYPTR(hh, conn_cache, &new_entry->key, sizeof(ConnKey), new_entry);
            // printf("KEY_ADDED\n");
        }
        return pid;
    }

    return pid;

}

// Expression Filtering
typedef enum {
    TOKEN_STRING,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_NOT,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_END
} ExprTokenType;

typedef struct {
    ExprTokenType type;
    char value[1024];
} ExprToken;

typedef enum {
    EXPR_STRING,
    EXPR_AND,
    EXPR_OR,
    EXPR_NOT
} ExprNodeType;

typedef struct ExprNode {
    ExprNodeType type;
    struct ExprNode* left;
    struct ExprNode* right;
    char value[1024]; // only for EXPR_STRING
} ExprNode;

#define MAX_TOKENS 128
ExprToken tokens[MAX_TOKENS];
int token_index = 0;
ExprNode* filter_root = NULL;

// Tokenizer: parses string like "#miner# or (#svchost# and !#windows#)"
void tokenize_expr(const char* expr) {
    int i = 0, t = 0;
    while (expr[i]) {
        while (isspace(expr[i])) i++;
        if (expr[i] == 0) break;

        if (expr[i] == '(') {
            tokens[t++] = (ExprToken){TOKEN_LPAREN, ""};
            i++;
        } else if (expr[i] == ')') {
            tokens[t++] = (ExprToken){TOKEN_RPAREN, ""};
            i++;
        } else if (expr[i] == '!') {
            tokens[t++] = (ExprToken){TOKEN_NOT, ""};
            i++;
        } else if (strncasecmp(&expr[i], "and", 3) == 0 && isspace(expr[i+3])) {
            tokens[t++] = (ExprToken){TOKEN_AND, ""};
            i += 3;
        } else if (strncasecmp(&expr[i], "or", 2) == 0 && isspace(expr[i+2])) {
            tokens[t++] = (ExprToken){TOKEN_OR, ""};
            i += 2;
        } else if (expr[i] == '#') {
            i++;
            int j = 0;
            char buffer[1024] = {0};
            while (expr[i] && expr[i] != '#' && j < 255) {
                buffer[j++] = tolower(expr[i++]);
            }
            buffer[j] = '\0';
            if (expr[i] == '#') i++;
            tokens[t].type = TOKEN_STRING;
            strncpy(tokens[t].value, buffer, sizeof(tokens[t].value));
            t++;
        } else {
            fprintf(stderr, "Unexpected character in expression: %c\n", expr[i]);
            exit(EXIT_FAILURE);
        }
    }
    tokens[t].type = TOKEN_END;
}

ExprToken* current_token() { return &tokens[token_index]; }
ExprToken* next_token() { return &tokens[++token_index]; }

ExprNode* parse_expr(); // forward
ExprNode* parse_factor();

ExprNode* parse_primary() {
    ExprToken* tok = current_token();
    if (tok->type == TOKEN_STRING) {
        ExprNode* node = malloc(sizeof(ExprNode));
        node->type = EXPR_STRING;
        strcpy(node->value, tok->value);
        node->left = node->right = NULL;
        next_token();
        return node;
    } else if (tok->type == TOKEN_LPAREN) {
        next_token();
        ExprNode* node = parse_expr();
        if (current_token()->type != TOKEN_RPAREN) {
            fprintf(stderr, "Unmatched parenthesis\n");
            exit(EXIT_FAILURE);
        }
        next_token();
        return node;
    } else {
        fprintf(stderr, "Unexpected token in primary\n");
        exit(EXIT_FAILURE);
    }
}

ExprNode* parse_factor() {
    if (current_token()->type == TOKEN_NOT) {
        next_token();
        ExprNode* node = malloc(sizeof(ExprNode));
        node->type = EXPR_NOT;
        node->left = parse_factor();
        node->right = NULL;
        return node;
    }
    return parse_primary();
}

ExprNode* parse_term() {
    ExprNode* node = parse_factor();
    while (current_token()->type == TOKEN_AND) {
        next_token();
        ExprNode* new_node = malloc(sizeof(ExprNode));
        new_node->type = EXPR_AND;
        new_node->left = node;
        new_node->right = parse_factor();
        node = new_node;
    }
    return node;
}

ExprNode* parse_expr() {
    ExprNode* node = parse_term();
    while (current_token()->type == TOKEN_OR) {
        next_token();
        ExprNode* new_node = malloc(sizeof(ExprNode));
        new_node->type = EXPR_OR;
        new_node->left = node;
        new_node->right = parse_term();
        node = new_node;
    }
    return node;
}

BOOL eval_expr(ExprNode* node, const char* path) {
    if (!node) return FALSE;
    switch (node->type) {
        case EXPR_STRING:
            return StrStrIA(path, node->value) != NULL;
        case EXPR_NOT:
            return !eval_expr(node->left, path);
        case EXPR_AND:
            return eval_expr(node->left, path) && eval_expr(node->right, path);
        case EXPR_OR:
            return eval_expr(node->left, path) || eval_expr(node->right, path);
        default:
            return FALSE;
    }
}

BOOL ShouldPrintPacket(const char* path) {
    if (!filter_root) return TRUE;
    return eval_expr(filter_root, path);
}

BOOL CheckFilterExpression(const char* expr)
{
    int len = strlen(expr);
    int paren_depth = 0;
    BOOL expect_operand = TRUE;

    for (int i = 0; i < len;)
    {
        // 跳过空白
        while (isspace(expr[i])) i++;

        if (expr[i] == '\0') break;

        if (expr[i] == '(')
        {
            paren_depth++;
            expect_operand = TRUE;
            i++;
        }
        else if (expr[i] == ')')
        {
            paren_depth--;
            if (paren_depth < 0) return FALSE;
            expect_operand = FALSE;
            i++;
        }
        else if (expr[i] == '!')
        {
            if (!expect_operand) return FALSE;
            i++;
        }
        else if (strncmp(&expr[i], "or", 2) == 0 && isspace(expr[i + 2]))
        {
            if (expect_operand) return FALSE;
            expect_operand = TRUE;
            i += 2;
        }
        else if (strncmp(&expr[i], "and", 3) == 0 && isspace(expr[i + 3]))
        {
            if (expect_operand) return FALSE;
            expect_operand = TRUE;
            i += 3;
        }
        else if (expr[i] == '#')
        {
            int start = i++;
            while (expr[i] != '\0' && expr[i] != '#') i++;
            if (expr[i] != '#') return FALSE; // 未闭合的关键词
            if (i == start + 1) return FALSE; // 空关键词 ##
            i++; // 跳过闭合 #
            expect_operand = FALSE;
        }
        else
        {
            // 非法字符
            return FALSE;
        }
    }

    return (paren_depth == 0 && !expect_operand);
}

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, console, process;
    UINT i;
    INT16 priority = 0;
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_ICMPHDR icmp_header;
    PWINDIVERT_ICMPV6HDR icmpv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    UINT32 src_addr[4], dst_addr[4];
    UINT64 hash;
    char src_str[INET6_ADDRSTRLEN+1], dst_str[INET6_ADDRSTRLEN+1];
    const char *err_str;
    LARGE_INTEGER base, freq;
    double time_passed;
    DWORD pid, path_len;
    char path[MAX_PATH+1];
    SYSTEMTIME st;
    char systemtime_str[32];
    char* filter_str = NULL;

    int filter_ip_version = 0;      // 0: all, 4: IPv4, 6: IPv6
    int filter_protocol = 0;        // 0: all, 1: ICMP, 6: TCP, 17: UDP
    BOOL enable_ipv4 = TRUE, enable_ipv6 = TRUE;
    BOOL enable_tcp = TRUE, enable_udp = TRUE, enable_icmp = TRUE;

    // Check arguments.
    if (argc < 2 || argc > 6) {
        fprintf(stderr, "Usage: %s windivert-filter [priority] [path-expression] [ipversion] [protocol]\n", argv[0]);
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s \"true\"\n", argv[0]);
        fprintf(stderr, "  %s \"outbound and tcp.DstPort == 80\" 1000\n", argv[0]);
        fprintf(stderr, "  %s \"inbound and tcp.Syn\" -400\n", argv[0]);
        fprintf(stderr, "  %s \"true\" 0 \"#miner# or (#svchost# and !#windows#)\"\n", argv[0]);
        fprintf(stderr, "  %s \"true\" 0 \"#miner# or (#svchost# and !#windows#)\" 4 6\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    // arg[1]: filter
    // arg[2]: priority
    if (argc > 2) {
        priority = (INT16)atoi(argv[2]);
    }
    // arg[3]: path
    if (argc > 3) {
        if (strlen(argv[3]) > 0 && _stricmp(argv[3], "true") != 0)
        {
            if (!CheckFilterExpression(argv[3]))
            {
                fprintf(stderr, "Invalid expression: %s\n", argv[3]);
                fprintf(stderr, "Example expressions:\n");
                fprintf(stderr, "  \"true\"\n");
                fprintf(stderr, "  \"#miner#\"\n");
                fprintf(stderr, "  \"!#<windows>#\"\n");
                fprintf(stderr, "  \"!#<unknown>#\"\n");
                fprintf(stderr, "  \"#miner# or #todesk#\"\n");
                fprintf(stderr, "  \"#svchost# and #windows#\"\n");
                fprintf(stderr, "  \"#miner# or (#windows# and !#svchost#)\"\n");
                exit(EXIT_FAILURE);
            }
            tokenize_expr(argv[3]);
            filter_root = parse_expr();
        }
    }
    // arg[4]: ipversion 0: all, 4: IPv4, 6: IPv6
    if (argc > 4) {
        if (strcmp(argv[4], "4") == 0) {
            enable_ipv6 = FALSE;
        } else if (strcmp(argv[4], "6") == 0) {
            enable_ipv4 = FALSE;
        }
    }
    // arg[5]: protocol 0: all, 1: ICMP, 6: TCP, 17: UDP
    if (argc > 5) {
        enable_tcp = enable_udp = enable_icmp = FALSE;
        if (strchr(argv[5], 't')) enable_tcp = TRUE;
        if (strchr(argv[5], 'u')) enable_udp = TRUE;
        if (strchr(argv[5], 'i')) enable_icmp = TRUE;
    }

    // Get console for pretty colors.
    console = GetStdHandle(STD_OUTPUT_HANDLE);

    // Divert traffic matching the filter:
    handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_FRAGMENTS);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(argv[1], WINDIVERT_LAYER_NETWORK,
                NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Max-out the packet queue:
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 
            WINDIVERT_PARAM_QUEUE_LENGTH_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue length (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME,
            WINDIVERT_PARAM_QUEUE_TIME_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue time (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_SIZE,
            WINDIVERT_PARAM_QUEUE_SIZE_MAX))
    {
        fprintf(stderr, "error: failed to set packet queue size (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }

    // Set up timing:
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&base);

    // 启动缓存表清理线程
    InitializeCriticalSection(&cache_lock);
    CreateThread(NULL, 0, CleanupCacheThread, NULL, 0, NULL);
    if (CleanupCacheThread == NULL)
    {
        fprintf(stderr, "error: failed to create cleanup thread.\n");
        exit(EXIT_FAILURE);
    }

    // Main loop:
    while (TRUE)
    {
        // Read a matching packet.
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packet_len, &addr))
        {
            fprintf(stderr, "warning: failed to read packet (%d)\n",
                GetLastError());
            continue;
        }

        // Print info about the matching packet.
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header,
            NULL, &icmp_header, &icmpv6_header, &tcp_header, &udp_header, NULL,
            NULL, NULL, NULL);
        if (ip_header == NULL && ipv6_header == NULL)
        {
            fprintf(stderr, "warning: junk packet\n");
        }

        // Process
        pid = FindProcessIdByTcpOrUdp(ip_header, ipv6_header, tcp_header, udp_header, &addr);
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        path_len = 0;
        if (process != NULL)
        {
            path_len = GetProcessImageFileName(process, path, sizeof(path));
            CloseHandle(process);
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_GREEN);
        const char* name = path;
        if (!path_len)
        {
            name = (pid == 4) ? "<Windows>" : "<Unknown>";
        }
        // path filter
        if (!ShouldPrintPacket(name)) {
            continue; // 跳过本次数据包处理
        }
        if ((ip_header && !enable_ipv4) || (ipv6_header && !enable_ipv6)){
            continue;
        }
        if ((tcp_header && !enable_tcp) ||
            (udp_header && !enable_udp) ||
            ((icmp_header || icmpv6_header) && !enable_icmp)){
                continue;
        }
        // Dump packet info:        
        putchar('\n');
        GetLocalTime(&st);
        snprintf(systemtime_str, sizeof(systemtime_str),
        "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        printf("%-24s\n", systemtime_str);
        printf("PROCESS [PID=%u Name=%s]\n", pid, name);
        SetConsoleTextAttribute(console, FOREGROUND_RED);
        time_passed = (double)(addr.Timestamp - base.QuadPart) /
            (double)freq.QuadPart;
        hash = WinDivertHelperHashPacket(packet, packet_len, 0);
        printf("Packet [Timestamp=%.8g, Direction=%s IfIdx=%u SubIfIdx=%u "
            "Loopback=%u Hash=0x%.16llX]\n",
            time_passed, (addr.Outbound?  "outbound": "inbound"),
            addr.Network.IfIdx, addr.Network.SubIfIdx, addr.Loopback, hash);
        if (ip_header != NULL)
        {
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->SrcAddr),
                src_str, sizeof(src_str));
            WinDivertHelperFormatIPv4Address(ntohl(ip_header->DstAddr),
                dst_str, sizeof(dst_str));
            SetConsoleTextAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED);
            printf("IPv4 [Version=%u HdrLength=%u TOS=%u Length=%u Id=0x%.4X "
                "Reserved=%u DF=%u MF=%u FragOff=%u TTL=%u Protocol=%u "
                "Checksum=0x%.4X SrcAddr=%s DstAddr=%s]\n",
                ip_header->Version, ip_header->HdrLength,
                ntohs(ip_header->TOS), ntohs(ip_header->Length),
                ntohs(ip_header->Id), WINDIVERT_IPHDR_GET_RESERVED(ip_header),
                WINDIVERT_IPHDR_GET_DF(ip_header),
                WINDIVERT_IPHDR_GET_MF(ip_header),
                ntohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header)), ip_header->TTL,
                ip_header->Protocol, ntohs(ip_header->Checksum), src_str,
                dst_str);
        }
        if (ipv6_header != NULL)
        {
            WinDivertHelperNtohIPv6Address(ipv6_header->SrcAddr, src_addr);
            WinDivertHelperNtohIPv6Address(ipv6_header->DstAddr, dst_addr);
            WinDivertHelperFormatIPv6Address(src_addr, src_str,
                sizeof(src_str));
            WinDivertHelperFormatIPv6Address(dst_addr, dst_str,
                sizeof(dst_str));
            SetConsoleTextAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED);
            printf("IPv6 [Version=%u TrafficClass=%u FlowLabel=%u Length=%u "
                "NextHdr=%u HopLimit=%u SrcAddr=%s DstAddr=%s]\n",
                ipv6_header->Version,
                WINDIVERT_IPV6HDR_GET_TRAFFICCLASS(ipv6_header),
                ntohl(WINDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header)),
                ntohs(ipv6_header->Length), ipv6_header->NextHdr,
                ipv6_header->HopLimit, src_str, dst_str);
        }
        if (icmp_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            printf("ICMP [Type=%u Code=%u Checksum=0x%.4X Body=0x%.8X]\n",
                icmp_header->Type, icmp_header->Code,
                ntohs(icmp_header->Checksum), ntohl(icmp_header->Body));
        }
        if (icmpv6_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_RED);
            printf("ICMPV6 [Type=%u Code=%u Checksum=0x%.4X Body=0x%.8X]\n",
                icmpv6_header->Type, icmpv6_header->Code,
                ntohs(icmpv6_header->Checksum), ntohl(icmpv6_header->Body));
        }
        if (tcp_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
            printf("TCP [SrcPort=%u DstPort=%u SeqNum=%u AckNum=%u "
                "HdrLength=%u Reserved1=%u Reserved2=%u Urg=%u Ack=%u "
                "Psh=%u Rst=%u Syn=%u Fin=%u Window=%u Checksum=0x%.4X "
                "UrgPtr=%u]\n",
                ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort),
                ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum),
                tcp_header->HdrLength, tcp_header->Reserved1,
                tcp_header->Reserved2, tcp_header->Urg, tcp_header->Ack,
                tcp_header->Psh, tcp_header->Rst, tcp_header->Syn,
                tcp_header->Fin, ntohs(tcp_header->Window),
                ntohs(tcp_header->Checksum), ntohs(tcp_header->UrgPtr));
        }
        if (udp_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
            printf("UDP [SrcPort=%u DstPort=%u Length=%u "
                "Checksum=0x%.4X]\n",
                ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort),
                ntohs(udp_header->Length), ntohs(udp_header->Checksum));
        }
        SetConsoleTextAttribute(console, FOREGROUND_GREEN | FOREGROUND_BLUE);
        for (i = 0; i < packet_len; i++)
        {
            if (i % HEXDUMP_COL == 0)
            {
                printf("\n\t");
            }
            printf("%.2X", (UINT8)packet[i]);
        }
        SetConsoleTextAttribute(console, FOREGROUND_RED | FOREGROUND_BLUE);
        for (i = 0; i < packet_len; i++)
        {
            if (i % (HEXDUMP_COL << 1) == 0)
            {
                printf("\n\t");
            }
            if (isprint(packet[i]))
            {
                putchar(packet[i]);
            }
            else
            {
                putchar('.');
            }
        }
        putchar('\n');
        SetConsoleTextAttribute(console,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        fflush(stdout);
    }

    DeleteCriticalSection(&cache_lock);
}

