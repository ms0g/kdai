#ifndef DHCP_H
#define DHCP_H

#include "common.h"

#define DHCP_CHADDR_LEN             16
#define DHCP_SNAME_LEN              64
#define DHCP_FILE_LEN               128

#define DHCP_SERVER_PORT            67
#define DHCP_CLIENT_PORT            68

#define DHCP_OPTION_MESSAGE_TYPE    0x35
#define DHCP_OPTION_LEASE_TIME      0x33
#define DHCP_OPTION_END             0xff

enum dhcp_message_type {
    DHCP_DISCOVER = 1,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_DECLINE,
    DHCP_ACK,
    DHCP_NAK,
    DHCP_RELEASE,
    DHCP_INFORM,
    DHCP_FORCERENEW,
    DHCP_LEASEQUERY,
    DHCP_LEASEUNASSIGNED,
    DHCP_LEASEUNKNOWN,
    DHCP_LEASEACTIVE,
};

struct dhcp {
    u8 opcode;
    u8 htype;
    u8 hlen;
    u8 hops;
    u32 xid;
    u16 secs;
    u16 flags;
    u32 ciaddr;
    u32 yiaddr;
    u32 siaddr;
    u32 giaddr;
    u8  chaddr[DHCP_CHADDR_LEN];
    u8  bp_sname[DHCP_SNAME_LEN];
    u8  bp_file[DHCP_FILE_LEN];
    u32 magic_cookie;
    u8  bp_options[];
} __attribute__((packed));

struct dhcp_snooping_entry {
    u32 ip;
    u8 mac[ETH_ALEN];
    u32 lease_time;
    u32 expires;
    struct list_head list;
};

extern struct task_struct* dhcp_thread;

int dhcp_is_valid(struct sk_buff* skb);

void insert_dhcp_snooping_entry(u8* mac, u32 ip, u32 lease_time, u32 expire_time);

struct dhcp_snooping_entry* find_dhcp_snooping_entry(u32 ip);

void delete_dhcp_snooping_entry(u32 ip);

void clean_dhcp_snooping_table(void);

int dhcp_thread_handler(void* arg);
#endif