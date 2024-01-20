#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

//operation for hooks
static struct nf_hook_ops forward_nh_ops;
static struct nf_hook_ops input_nh_ops;
static struct nf_hook_ops output_nh_ops;

//variables for creating sysfs device
static int major_number;
static struct class* FW_class = NULL;
static struct device* FW_device = NULL;
static struct file_operations fops = {
	.owner = THIS_MODULE 
	//no need for more operations becaause use of sysfs
};

//counters for communication with the user
static unsigned int count_dropped = 0;
static unsigned int count_accepted = 0;

//show implemantation- pass counters to user with \n delimeter
ssize_t show_c(struct device *dev, struct device_attribute *attr, char *buf)	
{
	return scnprintf(buf, PAGE_SIZE, "%u\n%u", count_dropped, count_accepted);
}

//store implementation- initialize counters by user's request
ssize_t initialize(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	count_dropped = 0;
 	count_accepted = 0;
	return 1;	
}

//define attributes for sysfs, premmisions, show, store
static DEVICE_ATTR(sysfs_att, S_IWUSR | S_IRUGO , show_c, initialize);

//hook functions:

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

//seting setting hook functions by hook point:

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
	int return_code;

	//create char device
	major_number = register_chrdev(0, "FW_Device", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	FW_class = class_create(THIS_MODULE, "FW_class");
	if (IS_ERR(FW_class))
	{
		unregister_chrdev(major_number, "FW_Device");
		return -1;
	}
	
	//create sysfs device
	FW_device = device_create(FW_class, NULL, MKDEV(major_number, 0), NULL, "FW_class" "_" "FW_Device");	
	if (IS_ERR(FW_device))
	{
		class_destroy(FW_class);
		unregister_chrdev(major_number, "FW_Device");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(FW_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
	{
		device_destroy(FW_class, MKDEV(major_number, 0));
		class_destroy(FW_class);
		unregister_chrdev(major_number, "FW_Device");
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
	//remove and destroy all the device's related objects
	device_remove_file(FW_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(FW_class, MKDEV(major_number, 0));
	class_destroy(FW_class);
	unregister_chrdev(major_number, "FW_Device");

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
