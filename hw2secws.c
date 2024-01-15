#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO and for the 						Macros */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops forward_nh_ops;
static struct nf_hook_ops input_nh_ops;
static struct nf_hook_ops output_nh_ops;

unsigned int drop_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	printk(KERN_INFO "*** Packet Dropped ***\n");
	return NF_DROP;
}

unsigned int accept_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	printk(KERN_INFO "*** Packet Accepted ***\n");
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
	int return_code;
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
	nf_unregister_net_hook(&init_net, &forward_nh_ops);
	nf_unregister_net_hook(&init_net, &input_nh_ops);
	nf_unregister_net_hook(&init_net, &output_nh_ops);
}
module_init(my_module_init_function);
module_exit(my_module_exit_function);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Basic kernel module firewall which allows connection to the FW and from the FW but not throught the FW");
