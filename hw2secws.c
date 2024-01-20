#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO and for the 						Macros */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops forward_nh_ops;
static struct nf_hook_ops input_nh_ops;
static struct nf_hook_ops output_nh_ops;

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

static unsigned int count_dropped = 0;
static unsigned int count_accepted = 0;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n%u\n", count_dropped, count_accepted);
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	/*int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		sysfs_int = temp;*/
	count_dropped = 0;
	count_accepted = 0;
	return 1;	
}

static DEVICE_ATTR(sysfs_att, S_IWUSR | S_IRUGO , display, modify);

unsigned int drop_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	printk(KERN_INFO "*** Packet Dropped ***\n");
	count_dropped++;
	return NF_DROP;
}

unsigned int accept_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	printk(KERN_INFO "*** Packet Accepted ***\n");
	count_accepted++;
	return NF_ACCEPT;
}

static int set_forward_hook(void){
	forward_nh_ops.hook = &drop_hookfn;
	forward_nh_ops.pf = PF_INET;
	forward_nh_ops.hooknum = NF_INET_FORWARD;
	forward_nh_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &forward_nh_ops);
}

static int set_input_hook(void){
	input_nh_ops.hook = &accept_hookfn;
	input_nh_ops.pf = PF_INET;
	input_nh_ops.hooknum = NF_INET_LOCAL_IN;
	input_nh_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &input_nh_ops);
}

static int set_output_hook(void){
	output_nh_ops.hook = &accept_hookfn;
	output_nh_ops.pf = PF_INET;
	output_nh_ops.hooknum = NF_INET_LOCAL_OUT;
	output_nh_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &output_nh_ops);
}

static int __init my_module_init_function(void) {
	//create char device
	int return_code;
	major_number = register_chrdev(0, "Sysfs_Device", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "Sysfs_class");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "sysfs_class" "_" "sysfs_Device");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	//Register hooks:
	if ((return_code = set_forward_hook()) !=0){
		return return_code; //if registration failed, return error
	}
	if ((return_code = set_input_hook()) !=0){
		return return_code; //if registration failed, return error
	}
	if ((return_code = set_output_hook()) !=0){
		return return_code; //if registration failed, return error
	}
	return 0; //registration succeeded
}
static void __exit my_module_exit_function(void) {
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "Sysfs_Device");
	//Unregister hooks:
	nf_unregister_net_hook(&init_net, &forward_nh_ops);
	nf_unregister_net_hook(&init_net, &input_nh_ops);
	nf_unregister_net_hook(&init_net, &output_nh_ops);
}
module_init(my_module_init_function);
module_exit(my_module_exit_function);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Basic kernel module firewall which allows connection to the FW and from the FW but not throught the FW");
