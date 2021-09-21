/**
 * @file kdai.c
 * @author M. Sami GURPINAR <sami.gurpinar@gmail.com>
 * @brief A LKM(Loadable Kernel Module) for detection and prevention of ARP Poisoning Attack.
 * @version 0.1
 *
 * @copyright Copyright (c) 2021 M. Sami GURPINAR
 *  
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *  
 * @license GPL-2.0+ <http://spdx.org/licenses/GPL-2.0+>
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/etherdevice.h>
#include <linux/neighbour.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/spinlock.h>
#include <linux/inetdevice.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <net/arp.h>
#include <net/udp.h>

#define DHCP_CHADDR_LEN     16
#define DHCP_SNAME_LEN      64
#define DHCP_FILE_LEN       128

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68

#define DHCP_OPTION_MESSAGE_TYPE    0x35
#define DHCP_OPTION_LEASE_TIME      0x33
#define DHCP_OPTION_END             0xff

#define eth_is_bcast(addr) (((addr)[0] & 0xffff) && ((addr)[2] & 0xffff) && ((addr)[4] & 0xffff))

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
    u_int8_t  opcode;
    u_int8_t  htype;
    u_int8_t  hlen;
    u_int8_t  hops;
    u_int32_t xid;
    u_int16_t secs;
    u_int16_t flags;
    u_int32_t ciaddr;
    u_int32_t yiaddr;
    u_int32_t siaddr;
    u_int32_t giaddr;
    u_int8_t  chaddr[DHCP_CHADDR_LEN];
    u_int8_t  bp_sname[DHCP_SNAME_LEN];
    u_int8_t  bp_file[DHCP_FILE_LEN];
    u_int32_t magic_cookie;
    u_int8_t  bp_options[];
} __attribute__((packed));

struct dhcp_snooping_entry {
    u_int32_t ip;
    u_int8_t mac[ETH_ALEN];
    u_int32_t lease_time;
    u_int32_t expires;
    struct list_head list;
};

static LIST_HEAD(dhcp_snooping_list);

static spinlock_t slock;
static struct task_struct *dhc_thread;
static struct nf_hook_ops *arpho = NULL;
static struct nf_hook_ops *ipho = NULL;

static void insert_dhcp_snooping_entry(u_int8_t *mac, u_int32_t ip, u_int32_t lease_time, u_int32_t expire_time);
static struct dhcp_snooping_entry *find_dhcp_snooping_entry(u_int32_t ip);
static void delete_dhcp_snooping_entry(u_int32_t ip);
static void clean_dhcp_snooping_table(void);

static int arp_is_valid(struct sk_buff *skb, u_int16_t ar_op, 
                        unsigned char *sha, u_int32_t sip, unsigned char *tha, u_int32_t tip);
static int dhcp_is_valid(struct sk_buff *skb);
static int dhc_th_func(void *arg);


static unsigned int arp_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct arphdr *arp;
    unsigned char *arp_ptr;
    unsigned char *sha,*tha;
    u_int32_t sip,tip;
    struct neighbour *hw;
    struct dhcp_snooping_entry *entry;
    struct net_device *dev = skb->dev;
    struct in_device *indev = in_dev_get(dev);
    struct in_ifaddr *ifa = indev->ifa_list;
    unsigned int status = NF_ACCEPT;
      
    if (unlikely(!skb))
        return NF_DROP;

    arp = arp_hdr(skb);
    arp_ptr = (unsigned char *)(arp + 1);
    sha	= arp_ptr;
    arp_ptr += dev->addr_len;
    memcpy(&sip, arp_ptr, 4);
    arp_ptr += 4;
    tha	= arp_ptr;
    arp_ptr += dev->addr_len;
    memcpy(&tip, arp_ptr, 4);

    if (arp_is_valid(skb, ntohs(arp->ar_op), sha, sip, tha, tip)) {
        for (;ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_address == tip) {
                hw = neigh_lookup(&arp_tbl, &sip, dev);   
                if (hw && memcmp(hw->ha, sha, dev->addr_len) != 0) {
                    status = NF_DROP;
                }
                
                entry = find_dhcp_snooping_entry(sip);
                if (entry && memcmp(entry->mac, sha, ETH_ALEN) != 0) {
                    printk(KERN_INFO "kdai:  ARP spoofing detected on %s from %pM\n", ifa->ifa_label, sha);
                    status = NF_DROP;
                } else status = NF_ACCEPT;             
        
                break;
            } else status = NF_DROP; 
        }
   
    } else status = NF_DROP;
    
    return status;
}


static unsigned int ip_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct udphdr *udp;
    struct dhcp *payload;
    unsigned char *opt;
    u_int8_t dhcp_packet_type;
    u_int32_t lease_time;
    struct timespec ts;
    struct dhcp_snooping_entry *entry;
    unsigned int status = NF_ACCEPT;

    if (unlikely(!skb))
        return NF_DROP;

    udp = udp_hdr(skb);
    
    if (udp->source == htons(DHCP_SERVER_PORT) || udp->source == htons(DHCP_CLIENT_PORT)) {
        payload = (struct dhcp *) ((unsigned char *)udp + sizeof(struct udphdr));
        
        if (dhcp_is_valid(skb)) {
            memcpy(&dhcp_packet_type, &payload->bp_options[2], 1);
            
            switch (dhcp_packet_type) {
                case DHCP_ACK:{
                    for (opt = payload->bp_options; *opt != DHCP_OPTION_END; opt += opt[1] + 2) {
                        if (*opt == DHCP_OPTION_LEASE_TIME) {
                            memcpy(&lease_time, &opt[2], 4);
                            break;
                        }
                    }
                    printk(KERN_INFO "kdai:  DHCPACK of %pI4\n", &payload->yiaddr);
                    getnstimeofday(&ts);
                    entry = find_dhcp_snooping_entry(payload->yiaddr);
                    if (entry) {
                        memcpy(entry->mac, payload->chaddr, ETH_ALEN);
                        entry->lease_time = ntohl(lease_time);
                        entry->expires = ts.tv_sec + ntohl(lease_time);
                    } else {
                        insert_dhcp_snooping_entry(payload->chaddr, payload->yiaddr, ntohl(lease_time), 
                                                    ts.tv_sec + ntohl(lease_time));
                    }
                    break;
                }
                case DHCP_RELEASE:{
                    printk(KERN_INFO "kdai:  DHCPRELEASE of %pI4\n", &payload->ciaddr);
                    delete_dhcp_snooping_entry(payload->ciaddr);
                    break;
                }
            default:
                break;
            }
      
        } else status = NF_DROP;
    }
   
    return status;
}


static int dhcp_is_valid(struct sk_buff *skb) {
    int status = 1;
    struct udphdr *udp;
    struct dhcp *payload;
    u_int8_t dhcp_packet_type;
    struct ethhdr *eth;
    unsigned char shaddr[ETH_ALEN];

    eth = eth_hdr(skb);
    memcpy(shaddr, eth->h_source, ETH_ALEN);

    udp = udp_hdr(skb);
    payload = (struct dhcp *) ((unsigned char *)udp + sizeof(struct udphdr));
    
    memcpy(&dhcp_packet_type, &payload->bp_options[2], 1);
    
    switch (dhcp_packet_type) {
        case DHCP_DISCOVER:
        case DHCP_REQUEST:{
            if (memcmp(payload->chaddr, shaddr, ETH_ALEN) != 0) {
                printk(KERN_INFO "kdai:  Invalid DHCP packet\n");
                status = 0;
            }
            break;
        }
        default:
            break;
    }
    
    if (payload->giaddr != 0) {
        printk(KERN_INFO "kdai:  Invalid DHCP packet\n");
        status = 0;
    }
    
    return status;
}


static int arp_is_valid(struct sk_buff *skb, u_int16_t ar_op, 
                        unsigned char *sha, u_int32_t sip, unsigned char *tha, u_int32_t tip)  {
    int status = 1;
    struct ethhdr *eth;
    unsigned char shaddr[ETH_ALEN],dhaddr[ETH_ALEN];

    eth = eth_hdr(skb);
    memcpy(shaddr, eth->h_source, ETH_ALEN);
    memcpy(dhaddr, eth->h_dest, ETH_ALEN);

    switch (ar_op) {
        case ARPOP_REQUEST:{
            if ((memcmp(sha, shaddr, ETH_ALEN) != 0) || !eth_is_bcast(dhaddr) || 
                ipv4_is_multicast(sip) || ipv4_is_loopback(sip) || ipv4_is_zeronet(sip)) {
                    printk(KERN_INFO "kdai:  Invalid ARP request from %pM\n", sha);
                    status = 0;
            }
            break;
        }
        case ARPOP_REPLY:{
            if ((memcmp(tha, dhaddr, ETH_ALEN) != 0) || (memcmp(sha, shaddr, ETH_ALEN) != 0) || 
                ipv4_is_multicast(tip) || ipv4_is_loopback(tip) || ipv4_is_zeronet(tip) || 
                ipv4_is_multicast(sip) || ipv4_is_loopback(sip) || ipv4_is_zeronet(sip)) {
                    printk(KERN_INFO "kdai:  Invalid ARP reply from %pM\n", sha);
                    status = 0;
            }
            break;
        }
        default:
            break;
    }

    return status;

}


static void insert_dhcp_snooping_entry(u_int8_t *mac, u_int32_t ip, u_int32_t lease_time, u_int32_t expire_time) {
    struct dhcp_snooping_entry *entry;
    unsigned long flags;

    entry = kmalloc(sizeof(struct dhcp_snooping_entry), GFP_KERNEL);
    entry->ip = ip;
    entry->lease_time = lease_time;
    entry->expires = expire_time;
    memcpy(entry->mac, mac, ETH_ALEN);
    
    spin_lock_irqsave(&slock, flags);
    
    list_add(&entry->list, &dhcp_snooping_list);
    
    spin_unlock_irqrestore(&slock, flags);
    
}


static struct dhcp_snooping_entry *find_dhcp_snooping_entry(u_int32_t ip) {
    struct list_head* curr,*next;
    struct dhcp_snooping_entry *entry;
    unsigned long flags;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &dhcp_snooping_list) {
        entry = list_entry(curr, struct dhcp_snooping_entry, list);
        if (entry->ip == ip) {
            spin_unlock_irqrestore(&slock, flags);
            return entry;
        }
    }
    spin_unlock_irqrestore(&slock, flags);
    return NULL;
}


static void delete_dhcp_snooping_entry(u_int32_t ip) {
    unsigned long flags;
    struct dhcp_snooping_entry *entry = find_dhcp_snooping_entry(ip);

    if (entry) {
        spin_lock_irqsave(&slock, flags);
        list_del(&entry->list);
        kfree(entry);
        spin_unlock_irqrestore(&slock, flags);
    }   
}


static void clean_dhcp_snooping_table(void) {
    struct list_head* curr, *next;
    struct dhcp_snooping_entry *entry;
    unsigned long flags;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &dhcp_snooping_list) {
        entry = list_entry(curr, struct dhcp_snooping_entry, list);
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&slock, flags);
}


static int dhc_th_func(void *arg) {
    struct list_head* curr, *next;
    struct dhcp_snooping_entry *entry;
    unsigned long flags;
    struct timespec ts;

    while(!kthread_should_stop()) {
        getnstimeofday(&ts);
        spin_lock_irqsave(&slock, flags);
        list_for_each_safe(curr, next, &dhcp_snooping_list) {
            entry = list_entry(curr, struct dhcp_snooping_entry, list);
            if (ts.tv_sec >= entry->expires) {
                printk(KERN_INFO "kdai:  %pI4 released on %ld\n", &entry->ip, ts.tv_sec);
                list_del(&entry->list);
                kfree(entry);
            }
        }
        spin_unlock_irqrestore(&slock, flags);
        msleep(1000);
    }
    return 0;
}

    
static int __init kdai_init(void) {
    /* Initialize arp netfilter hook */
    arpho = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    arpho->hook = (nf_hookfn *) arp_hook;       /* hook function */
    arpho->hooknum = NF_ARP_IN;                 /* received packets */
    arpho->pf = NFPROTO_ARP;                    /* ARP */
    arpho->priority = NF_IP_PRI_FIRST;
    nf_register_hook(arpho);
    
    /* Initialize ip netfilter hook */
    ipho = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    ipho->hook = (nf_hookfn *) ip_hook;         /* hook function */
    ipho->hooknum = NF_INET_PRE_ROUTING;        /* received packets */
    ipho->pf = NFPROTO_IPV4;                    /* IP */
    ipho->priority = NF_IP_PRI_FIRST;
    nf_register_hook(ipho);

    spin_lock_init(&slock);
    dhc_thread = kthread_run(dhc_th_func, NULL, "DHCP Thread");
    if(dhc_thread) {
        printk(KERN_INFO"kdai:  DHCP Thread Created Successfully...\n");
    } else {
        printk(KERN_INFO"kdai:  Cannot create kthread\n");
    }
    return 0; 
}


static void __exit kdai_exit(void) {
    nf_unregister_hook(arpho);
    kfree(arpho);
    nf_unregister_hook(ipho);
    kfree(ipho);
    clean_dhcp_snooping_table();
    kthread_stop(dhc_thread);
}

module_init(kdai_init);
module_exit(kdai_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M. Sami GURPINAR <sami.gurpinar@gmail.com>");
MODULE_DESCRIPTION("A lkm for detection and prevention of Arp Poisoning");
MODULE_VERSION("0.1"); 
