#include "trustedInterfaces.h"
#include "errno.h"

LIST_HEAD(trusted_interface_list);  // Global list head for interfaces
static int trusted_list_size = 0;

// Function to populate the list with all interfaces as trusted
void populate_trusted_interface_list(void) {
    struct net_device *dev;
    
    // Iterate over all network interfaces
    for_each_netdev(&init_net, dev) {
        struct interface_entry *new_entry;

        // Allocate memory for new entry, using kmalloc, the kernel equivalent of malloc
        // GFP_KERNEL allows for blocking. Default for most kernel allocaitons
        new_entry = kmalloc(sizeof(struct interface_entry), GFP_KERNEL);

        //If memmory could not be allocated return
        if (!new_entry) {
            printk(KERN_ERR "kdai: Memory allocation failed for interface entry\n");
            return;
        }

        // Copy interface name and add to list
        strncpy(new_entry->name, dev->name, IFNAMSIZ - 1);
        new_entry->name[IFNAMSIZ - 1] = '\0';  // Ensure null termination
        list_add_tail(&new_entry->list, &trusted_interface_list);
        trusted_list_size++;
    }
}

void insert_trusted_interface(const char *device_name) {

    struct interface_entry *new_entry;

    //If we found that device already return
    if(find_trusted_interface(device_name)){
        return;
    }

    // Allocate memory for the new entry
    new_entry = kmalloc(sizeof(struct interface_entry), GFP_KERNEL);
    if (!new_entry) {
        printk(KERN_ERR "Failed to allocate memory for interface entry\n");
        return;
    }

    // Copy the device name safely
    strncpy(new_entry->name, device_name, IFNAMSIZ - 1);
    new_entry->name[IFNAMSIZ - 1] = '\0'; // Ensure null termination

    // Add to the end of the list
    list_add_tail(&new_entry->list, &trusted_interface_list);
    trusted_list_size++;

    printk(KERN_INFO "Added interface: %s\n", new_entry->name);
}

//Function to find an interface in the trusted list. Will return the device if the interface is trusted.
//Will return NULL if the device was not found
const char* find_trusted_interface(const char *interface_name) {
    struct interface_entry *entry;

    // Loop through the list to find a matching interface name
    list_for_each_entry(entry, &trusted_interface_list, list) {
        if (strncmp(entry->name, interface_name, IFNAMSIZ) == 0) {
            return entry->name; // Interface found, return interface
        }
    }

    return NULL; // Interface not found, return NULL
}

// Function to print all interfaces in the list
void print_trusted_interface_list(void) {
    struct interface_entry *entry;

    printk(KERN_INFO "kdai: List of trusted network interfaces:\n");

    if(trusted_list_size == 0) {
        printk(KERN_INFO "!!(The list is currently empty) All interfaces are assumed Untrusted!!\n");
        return;
    }

    list_for_each_entry(entry, &trusted_interface_list, list) {
        printk(KERN_INFO " - %s\n", entry->name);
    }
}

// Function to free the list during module cleanup
void free_trusted_interface_list(void) {
    struct interface_entry *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &trusted_interface_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

