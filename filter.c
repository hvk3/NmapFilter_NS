#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfho;

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);

	if (iph -> protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	if (tcph -> fin && tcph -> psh && tcph -> urg)
		printk("(filter.c) Xmas scan packet logged.\n");
	else if (tcph -> ack && tcph -> fin && !(tcph -> psh && tcph -> urg && tcph -> syn && tcph -> rst && tcph -> ece && tcph -> cwr))
		printk("(filter.c) TCP Maimon scan packet logged.\n");
	else if (tcph -> fin && !(tcph -> psh && tcph -> urg && tcph -> syn && tcph -> ack && tcph -> rst && tcph -> ece && tcph -> cwr))
		printk("(filter.c) FIN scan packet logged.\n");
	else if (!(tcph -> fin && tcph -> psh && tcph -> urg && tcph -> syn && tcph -> ack && tcph -> rst && tcph -> ece && tcph -> cwr))
		printk("(filter.c) Null scan packet logged.\n");
	return NF_ACCEPT;
}

int init_module()
{
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&nfho);
}