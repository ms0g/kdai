#include "trustedInterfaces.h"
#include "errno.h"

LIST_HEAD(trusted_interface_list);  // Global list head for interfaces
static int trusted_list_size = 0;

/**
 * populate_trusted_interface_list - Populate the trusted interface list with all network interfaces.asm
 * 
 * This function iterates over all netowrk interfaces in the system and inserts each one into the
 * the trusted interface list.
 * 
 */
void populate_trusted_interface_list(void) {
    struct net_device *dev;
    // Iterate over all network interfaces
    for_each_netdev(&init_net, dev) {
        insert_trusted_interface(dev->name);
    }
}

/**
 * insert_trusted_interface - Insert a new interface into the trusted list.
 * @device_name: The name of the trusted interface to insert
 * 
 * This fucntion inserts the name of a network interface into teh trusted interface list. 
 * It first checks if the interface already exists in the list using find_trusted_interface. 
 * If the interface is not found it alloactes memory for a new entry, and cpoies the device name. 
 * The list field is the intialized for the new entry and this fucntion adds the new entry to
 * the end fo the lis tusing list_add_tail. The trusted_list_size if then incremented, and 
 * a message is printed to indicate the enw addition.asm
 * 
 * Return: This fucntion returns 1 if the interface name was added, 0 if it already exists,
 * and -1 if mmory allocaiton failed
 */
int insert_trusted_interface(const char *device_name) {

    struct interface_entry *new_entry;

    //If we found that device already return
    if(find_trusted_interface(device_name)){
        return 0;
    }

    // Allocate memory for the new entry
    new_entry = kmalloc(sizeof(struct interface_entry), GFP_KERNEL);
    if (!new_entry) {
        printk(KERN_ERR "Failed to allocate memory for interface entry\n");
        return -1;
    }

    // Copy the device name safely
    strncpy(new_entry->name, device_name, IFNAMSIZ - 1);
    new_entry->name[IFNAMSIZ - 1] = '\0'; // Ensure null termination

    // Initialize the list field of the new entry
    INIT_LIST_HEAD(&new_entry->list);

    // Add to the end of the list
    list_add_tail(&new_entry->list, &trusted_interface_list);
    trusted_list_size++;

    printk(KERN_INFO "Added interface: %s\n", new_entry->name);

    return 1;
}

/**
 * find_trusted_interface - Find an interface in the trusted list.
 * @interface_name: The name of the interaface to find
 * 
 * This function searches the trusted interface list for an entry that matches the given interface name.
 * If a matching entry is found, the function returns the name of th einterface. If no match is found the
 * function returns NULL.
 * 
 * Return: The name of the trusted interface if found, or NULL if not found.
 */
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

/**
 * print_trusted_interface_list - Print all interfaces in the trusted list
 * 
 * This function prints the names of all network interfaces in the trusted interface list.
 * If the list is empty, it prints a message indicaitng that all interfaces are assumed to be Untrusted.
 * 
 * Return: This function does not return a value
 */
void print_trusted_interface_list(void) {
    struct interface_entry *entry;

    printk(KERN_INFO "kdai: List of trusted network interfaces:\n");

    //If the list is empty notify the user
    if(trusted_list_size == 0) {
        printk(KERN_INFO "!!(The list is currently empty) All interfaces are assumed Untrusted!!\n");
        return;
    }

    //Iterate and print each entry
    list_for_each_entry(entry, &trusted_interface_list, list) {
        printk(KERN_INFO " - %s\n", entry->name);
    }
}

/**
 * free_trusted_interface_list - Free all entries in the trusted interface list
 * 
 * This function iterates through the trusted interface list and frees each entry.
 * It uses list_for_each_entry_safe to  traverse the list while deleting entries. 
 * This means it uses an additional temporary pointer to store the next entry before 
 * deleting the currnet one Each entry is removed from the list using list_del and 
 * then freed using kfree.
 * 
 * Return: this function does not return anything
 */
void free_trusted_interface_list(void) {
    struct interface_entry *entry, *tmp;

    //Iterate through the list, del and free each entry.
    list_for_each_entry_safe(entry, tmp, &trusted_interface_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

