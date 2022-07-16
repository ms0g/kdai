
#include "dhcp.h"
#include "errno.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("M. Sami GURPINAR <sami.gurpinar@gmail.com>");
MODULE_DESCRIPTION("kdai(Kernel Dynamic ARP Inspection) is a linux kernel module to defend against arp spoofing");
MODULE_VERSION("0.1"); 

#define eth_is_bcast(addr) (((addr)[0] & 0xffff) && ((addr)[2] & 0xffff) && ((addr)[4] & 0xffff))

static struct nf_hook_ops* arpho = NULL;
static struct nf_hook_ops* ipho = NULL;

static int arp_is_valid(struct sk_buff* skb, u16 ar_op, unsigned char* sha, 
                        u32 sip, unsigned char* tha, u32 tip);

static unsigned int arp_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct arphdr* arp;
    unsigned char* arp_ptr;
    unsigned char* sha, *tha;
    struct net_device* dev;
    struct in_device* indev;
    struct in_ifaddr* ifa;
    struct neighbour* hw;
    struct dhcp_snooping_entry* entry;
    unsigned int status = NF_ACCEPT;
    u32 sip, tip;
      
    if (unlikely(!skb))
        return NF_DROP;

    dev = skb->dev;
    indev = in_dev_get(dev);
    
    arp = arp_hdr(skb);
    arp_ptr = (unsigned char *)(arp + 1);
    sha	= arp_ptr;
    arp_ptr += dev->addr_len;
    memcpy(&sip, arp_ptr, 4);
    arp_ptr += 4;
    tha	= arp_ptr;
    arp_ptr += dev->addr_len;
    memcpy(&tip, arp_ptr, 4);

    if (arp_is_valid(skb, ntohs(arp->ar_op), sha, sip, tha, tip) == 0) {
        for (ifa = indev->ifa_list; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_address == tip) {
                // querying arp table
                hw = neigh_lookup(&arp_tbl, &sip, dev);
                if (hw && memcmp(hw->ha, sha, dev->addr_len) != 0) {
                    status = NF_DROP;
                    neigh_release(hw);
                }
                // querying dhcp snooping table
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


static unsigned int ip_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct udphdr* udp;
    struct dhcp* payload;
    unsigned char* opt;
    u8 dhcp_packet_type;
    u32 lease_time;
    struct timespec ts;
    struct dhcp_snooping_entry* entry;
    unsigned int status = NF_ACCEPT;

    if (unlikely(!skb))
        return NF_DROP;

    udp = udp_hdr(skb);
    
    if (udp->source == htons(DHCP_SERVER_PORT) || udp->source == htons(DHCP_CLIENT_PORT)) {
        payload = (struct dhcp *) ((unsigned char *)udp + sizeof(struct udphdr));
        
        if (dhcp_is_valid(skb) == 0) {
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
                        insert_dhcp_snooping_entry(
                            payload->chaddr, payload->yiaddr, ntohl(lease_time), ts.tv_sec + ntohl(lease_time));
                    }
                    break;
                }
                
                case DHCP_NAK:{
                    printk(KERN_INFO "kdai:  DHCPNAK of %pI4\n", &payload->yiaddr);
                    entry = find_dhcp_snooping_entry(payload->yiaddr);
                    if (entry) {
                        delete_dhcp_snooping_entry(entry->ip);
                    }
                    break;
                }

                case DHCP_RELEASE:{
                    printk(KERN_INFO "kdai:  DHCPRELEASE of %pI4\n", &payload->ciaddr);
                    delete_dhcp_snooping_entry(payload->ciaddr);
                    break;
                }

                case DHCP_DECLINE:{
                    printk(KERN_INFO "kdai:  DHCPDECLINE of %pI4\n", &payload->ciaddr);
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


static int arp_is_valid(struct sk_buff* skb, u16 ar_op, unsigned char* sha, 
                                u32 sip, unsigned char* tha, u32 tip)  {
    int status = SUCCESS;
    const struct ethhdr* eth;
    unsigned char shaddr[ETH_ALEN],dhaddr[ETH_ALEN];

    eth = eth_hdr(skb);
    memcpy(shaddr, eth->h_source, ETH_ALEN);
    memcpy(dhaddr, eth->h_dest, ETH_ALEN);

    if (memcmp(sha, shaddr, ETH_ALEN) != 0) {
        printk(KERN_ERR "kdai:  the sender MAC address %pM in the message body is NOT identical to the source MAC address in the Ethernet header %pM\n", sha, shaddr);
        return -EHWADDR;
    } 

    if (ipv4_is_multicast(sip)) {
        printk(KERN_ERR "kdai:  the sender ip address %pI4 is multicast\n", &sip);
        return -EIPADDR;
    }

    if (ipv4_is_loopback(sip)) {
        printk(KERN_ERR "kdai:  the sender ip address %pI4 is loopback\n", &sip);
        return -EIPADDR;
    }

    if (ipv4_is_zeronet(sip)) {
        printk(KERN_ERR "kdai:  the sender ip address %pI4 is zeronet\n", &sip);
        return -EIPADDR;
    } 
            
    if (ipv4_is_multicast(tip)) {
        printk(KERN_ERR "kdai:  the target ip address %pI4 is multicast\n", &tip);
        return -EIPADDR;
    }
            
    if (ipv4_is_loopback(tip)) {
        printk(KERN_ERR "kdai:  the target ip address %pI4 is loopback\n", &tip);
        return -EIPADDR;
    }
            
    if (ipv4_is_zeronet(tip)) {
        printk(KERN_ERR "kdai:  the target ip address %pI4 is zeronet\n", &tip);
        return -EIPADDR;
    }

    if (ar_op == ARPOP_REPLY) {
         if (memcmp(tha, dhaddr, ETH_ALEN) != 0) {
            printk(KERN_ERR "kdai:  the target MAC address %pM in the message body is NOT identical" 
                            "to the destination MAC address in the Ethernet header %pM\n", tha, dhaddr);
            return -EHWADDR;
         }
    }
    return status;

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
    
    dhcp_thread = kthread_run(dhcp_thread_handler, NULL, "DHCP Thread");
    if(dhcp_thread) {
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
    kthread_stop(dhcp_thread);
}

module_init(kdai_init);
module_exit(kdai_exit);
