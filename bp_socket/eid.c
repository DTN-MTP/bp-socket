#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/printk.h>
#include "../include/bp_socket.h"
#include "eid.h"

enum bp_eid_scheme parse_eid_scheme(char *cursor, int eid_size)
{
    if (eid_size == 3 && strncmp(cursor, "ipn", 3) == 0)
        return IPN;
    return UNKNOWN_SCHEME;
}

int str_find_char_bounded(char *cursor, char target, int *remaining)
{
    char *start = cursor;
    char *end = cursor + *remaining;

    while (cursor < end && *cursor != target && *cursor != '\0')
        cursor++;

    if (cursor < end && *cursor == target)
    {
        int read = cursor - start;
        *remaining -= (read + 1);
        return read;
    }

    return -1;
}

int str_find_term_bounded(char *cursor, int *remaining)
{
    char *start = cursor;
    char *end = cursor + *remaining;

    while (*cursor != '\0' && cursor < end)
        cursor++;

    if (*cursor == '\0')
    {
        int read = cursor - start;
        *remaining -= read;
        return read;
    }

    return -1;
}

int str_read_uint_bounded(const char *str, size_t len)
{
    int result = 0;
    for (size_t i = 0; i < len; i++)
    {
        if (!isdigit(str[i]))
            return -1;
        result = result * 10 + (str[i] - '0');
    }
    return result;
}

int ipn_eid_parse(char *cursor, int remaining)
{
    int dotpos = str_find_char_bounded(cursor, '.', &remaining);
    int node_id = str_read_uint_bounded(cursor, dotpos);
    if (node_id < 0)
    {
        pr_err("ipn_eid_parse: invalid node id\n");
        return -1;
    }

    cursor += dotpos + 1;
    int endpos = str_find_term_bounded(cursor, &remaining);
    int service_id = str_read_uint_bounded(cursor, endpos);
    if (service_id < 0)
    {
        pr_err("ipn_eid_parse: invalid service id\n");
        return -2;
    }

    pr_info("ipn_eid_parse: node %d and service %d\n", node_id, service_id);
    return service_id;
}

int get_service_id(const char *eid_str)
{
    int remaining = sizeof(((struct sockaddr_bp *)0)->eid_str);
    char *cursor = (char *)eid_str;
    int colonpos = str_find_char_bounded(cursor, ':', &remaining);
    enum bp_eid_scheme eid_type = parse_eid_scheme(cursor, colonpos);
    cursor += colonpos + 1;

    switch (eid_type)
    {
    case IPN:
        return ipn_eid_parse(cursor, remaining);
    default:
        pr_err("get_service_id: unknown EID scheme\n");
        return -1;
    }
}
