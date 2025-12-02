#include "tcpTable.h"

tcp_table tcpTableInit(void)
{
    tcp_table t;
    for (int i = 0; i < TABLE_SIZE; i++)
    {
        tcp_table.connections[i].id = -1;
    }

    return t;
}
