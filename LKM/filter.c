#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#define MAX_RULES_NUM 5

char input_rules[100];//5*20
char output_rules[100];//5*20
char choice[1];//用于删除
int in_num = 0;//INPUT链规则数量
int out_num = 0;//OUTPUT链规则数量

static struct nf_hook_ops myhook1, myhook2;

struct Rule{//20Bytes
	int src_port;//源端口
	int dst_port;//目的端口
	unsigned int src_addr;//源地址
	unsigned int dst_addr;//目的地址
	int protocol;//协议
}inputList[MAX_RULES_NUM], outputList[MAX_RULES_NUM];//全局规则列表
//字符串流转规则
struct Rule stringToRule(char* rules_pointer){
	struct Rule onerule;
	onerule.src_port = *(int *)rules_pointer;
	onerule.dst_port = *(int *)(rules_pointer + 4);
	onerule.src_addr = *(int *)(rules_pointer + 8);
	onerule.dst_addr = *(int *)(rules_pointer + 12);
	onerule.protocol = *(int *)(rules_pointer + 16);
	return onerule;
}
//规则转字符串流
void ruleToString(struct Rule onerule, char* rules_pointer){
	*(int *)rules_pointer = onerule.src_port;
	*(int *)(rules_pointer + 4) = onerule.dst_port;
	*(int *)(rules_pointer + 8) = onerule.src_addr;
	*(int *)(rules_pointer + 12) = onerule.dst_addr;
	*(int *)(rules_pointer + 16) = onerule.protocol;
}
//判断端口是否匹配
int is_port(struct Rule onerule, int src_port, int dst_port){//return: 1-match this rule in port, 0-not match
	if(onerule.src_port == 0 && onerule.dst_port == 0)
		return 1;
	if(onerule.src_port != 0 && onerule.dst_port == 0){
		if(onerule.src_port == src_port)
			return 1;
		else
			return 0;
	}
	if(onerule.src_port == 0 && onerule.dst_port != 0){
		if(onerule.dst_port == dst_port)
			return 1;
		else
			return 0;
	}
	if(onerule.src_port != 0 && onerule.dst_port != 0){
		if(onerule.src_port == src_port && onerule.dst_port == dst_port)
			return 1;
		else
			return 0;
	}
	return 0;
}
//判断ip是否匹配
int is_ipaddr(struct Rule onerule, int src_addr, int dst_addr){//return: 1-match this rule in ip address, 0-not match
	if(onerule.src_addr == 0 && onerule.dst_addr == 0)
		return 1;
	if(onerule.src_addr != 0 && onerule.dst_addr == 0){
		if(onerule.src_addr == src_addr)
			return 1;
		else
			return 0;
	}
	if(onerule.src_addr == 0 && onerule.dst_addr != 0){
		if(onerule.dst_addr == dst_addr)
			return 1;
		else
			return 0;
	}
	if(onerule.src_addr != 0 && onerule.dst_addr != 0){
		if(onerule.src_addr == src_addr && onerule.dst_addr == dst_addr)
			return 1;
		else
			return 0;
	}
	return 0;
}
//INPUT钩子函数
unsigned int input_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	struct udphdr *udph = udp_hdr(skb);
	struct Rule onerule;
	int i, result=0;
	char sip[16],dip[16];
	//将32位二进制ip转换为点分十进制，输出时会用
	sprintf(sip,"%d.%d.%d.%d",(iph->saddr)&0xff,((iph->saddr)>>8)&0xff,((iph->saddr)>>16)&0xff,((iph->saddr)>>24)&0xff);
	sprintf(dip,"%d.%d.%d.%d",(iph->daddr)&0xff,((iph->daddr)>>8)&0xff,((iph->daddr)>>16)&0xff,((iph->daddr)>>24)&0xff);
	//printk(KERN_INFO "PRE ROUTING HOOK is active.\n");
	if(in_num == 0)//规则为0时均通过
		return NF_ACCEPT;
	else{
		for(i = 0; i<in_num; i++){//遍历规则列表
			onerule = inputList[i];
			//校验是否符合每条规则
			if(onerule.protocol == 10 && iph->protocol == IPPROTO_TCP){
				if(is_ipaddr(onerule, iph->saddr, iph->daddr) && is_port(onerule, ntohs(tcph->source),ntohs(tcph->dest))){
					printk(KERN_INFO "FireWall PRE_ROUTING CHAIN: TCP packet from %s to %s was rejected.",sip,dip);
					result = 1;
				}
			}
			else if(onerule.protocol == 11 && iph->protocol == IPPROTO_UDP){
				if(is_ipaddr(onerule, iph->saddr, iph->daddr) && is_port(onerule, ntohs(udph->source),ntohs(udph->dest))){
					printk(KERN_INFO "FireWall PRE_ROUTING CHAIN: UDP packet from %s to %s was rejected.",sip,dip);
					result = 1;
				}
			}
			else if(onerule.protocol == 12 && iph->protocol == IPPROTO_ICMP){
				if(is_ipaddr(onerule, iph->saddr, iph->daddr)){
					printk(KERN_INFO "FireWall PRE_ROUTING CHAIN: ICMP packet from %s to %s was rejected.",sip,dip);
					result = 1;
				}
			}
			else if(onerule.protocol == 0){
				if(is_ipaddr(onerule, iph->saddr, iph->daddr)){
					printk(KERN_INFO "FireWall PRE_ROUTING CHAIN: packet from %s to %s was rejected.",sip,dip);
					result = 1;
				}
			}
			if(result == 0)
				continue;
			else
				return NF_DROP;//符合某条规则则过滤
		}
		return NF_ACCEPT;//均不符合则通过
	}
}
//OUTPUT钩子函数，同理
unsigned int output_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	struct udphdr *udph = udp_hdr(skb);
	struct Rule onerule;
	int i, result=0;
	char sip[16],dip[16];
	sprintf(sip,"%d.%d.%d.%d",(iph->saddr)&0xff,((iph->saddr)>>8)&0xff,((iph->saddr)>>16)&0xff,((iph->saddr)>>24)&0xff);
	sprintf(dip,"%d.%d.%d.%d",(iph->daddr)&0xff,((iph->daddr)>>8)&0xff,((iph->daddr)>>16)&0xff,((iph->daddr)>>24)&0xff);
	if(out_num == 0)
		return NF_ACCEPT;
	else{
		for(i = 0; i<out_num; i++){
			onerule = outputList[i];
			if(onerule.protocol == 10 && iph->protocol == IPPROTO_TCP){
				if(is_ipaddr(onerule, iph->saddr, iph->daddr) && is_port(onerule, ntohs(tcph->source),ntohs(tcph->dest))){
					printk(KERN_INFO "FireWall POST_ROUTING CHAIN: TCP packet from %s to %s was rejected.",sip,dip);
					result = 1;
				}
			}
			else if(onerule.protocol == 11 && iph->protocol == IPPROTO_UDP){
				if(is_ipaddr(onerule, iph->saddr, iph->daddr) && is_port(onerule, ntohs(udph->source),ntohs(udph->dest))){
					printk(KERN_INFO "FireWall POST_ROUTING CHAIN: UDP packet from %s to %s was rejected.",sip,dip);
					result = 1;
				}
			}
			else if(onerule.protocol == 12 && iph->protocol == IPPROTO_ICMP){
				if(is_ipaddr(onerule, iph->saddr, iph->daddr)){
					printk(KERN_INFO "FireWall POST_ROUTING CHAIN: ICMP packet from %s to %s was rejected.",sip,dip);
					result = 1;
				}
			}
			else if(onerule.protocol == 0){
				if(is_ipaddr(onerule, iph->saddr, iph->daddr)){
					printk(KERN_INFO "FireWall POST_ROUTING CHAIN: packet from %s to %s was rejected.",sip,dip);
					result = 1;
				}
			}
			if(result == 0)
				continue;
			else
				return NF_DROP;
		}
		return NF_ACCEPT;
	}
}



static ssize_t get_input_rules(struct file *fd, const char __user *buf, size_t len, loff_t *ppos){
	struct Rule onerule;//定义规则变量
	if(len == 0)//若用户态传入的字符串长度为0，则直接返回
		return in_num;//in_num为INPUT链中规则数量
	if(copy_from_user(input_rules, buf, len)!=0){
		//该函数从用户态buf中将长度为len的数据复制到input_rules
		printk("Can't get the rules!\n");
		return 0;
	}
	onerule = stringToRule(input_rules);//将输入的字符串规则数据转换成自定义的规则对象
	inputList[in_num] = onerule;//将获得的规则存储至全局规则数组中
	in_num++;//规则数量+1
	return in_num;
}
//同理
static ssize_t get_output_rules(struct file *fd, const char __user *buf, size_t len, loff_t *ppos){
	struct Rule onerule;
	if(len == 0)
		return out_num;
	if(copy_from_user(output_rules, buf, len)!=0){
		printk("Can't get the rules!\n");
		return 0;
	}
	onerule = stringToRule(output_rules);
	outputList[out_num] = onerule;
	out_num++;
	return out_num;
}

static ssize_t read_input_rules(struct file *fd, char __user *buf, size_t len, loff_t *ppos){
	int i;
	for(i=0;i<in_num;i++){//将当前规则列表中的所有规则首先都处理成字符串流
		ruleToString(inputList[i], (input_rules+(i*20)));//1条规则20字节
	}
	len = in_num*20;//总长度等于数量*20
	if(copy_to_user(buf, input_rules, len)!=0){//该函数将字符串流传给用户态的buf数组
		printk("Can't read the rules!\n");
		return 0;
	}
	return in_num;//返回当前总共有多少条规则
}
//同理
static ssize_t read_output_rules(struct file *fd, char __user *buf, size_t len, loff_t *ppos){
	int i;
	for(i=0;i<out_num;i++){
		ruleToString(outputList[i], (output_rules+(i*20)));
	}
	len = out_num*20;
	if(copy_to_user(buf, output_rules, len)!=0){
		printk("Can't read the rules!\n");
		return 0;
	}
	return out_num;
}

static ssize_t delete(struct file *fd, const char __user *buf, size_t len, loff_t *ppos){
	if(len == 0)//传入字符为空直接返回
		return 0;
	if(copy_from_user(choice, buf, len)!=0){//接受用户的指令存入choice
		printk("Can't get the information!\n");
		return 0;
	}
	if(choice[0]=='1')//清空INPUT链
		in_num = 0;
	else
		out_num = 0;//清空OUTPUT链
	return 1;
}

struct file_operations fops1 = {
	.owner = THIS_MODULE,//拥有者
	.write = get_input_rules,//write系统调用时触发的操作函数
	.read = read_input_rules,//read系统调用时触发的操作函数
};
//同理
struct file_operations fops2 = {
	.owner = THIS_MODULE,
	.write = get_output_rules,
	.read = read_output_rules,
};
//删除操作对应的设备文件操作符
struct file_operations fops3 = {
	.owner = THIS_MODULE,
	.write = delete,
};
//注册
int __init registerFilter(void){
	int ret1, ret2, ret3;
	printk("Init Module\n");
	
	myhook1.hook = input_hook_func;
	myhook1.hooknum = NF_INET_PRE_ROUTING;
	myhook1.pf = PF_INET;
	myhook1.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &myhook1);
	
	myhook2.hook = output_hook_func;
	myhook2.hooknum = NF_INET_POST_ROUTING;
	myhook2.pf = PF_INET;
	myhook2.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &myhook2);
	
	ret1 = register_chrdev(124, "/dev/inputRules", &fops1);
	ret2 = register_chrdev(125, "/dev/outputRules", &fops2);
	ret3 = register_chrdev(126, "/dev/Delete", &fops3);
	if(ret1 != 0)
		printk("Cna't register device inputRules!\n");
	if(ret2 != 0)
		printk("Cna't register device outputRules!\n");
	if(ret3 != 0)
		printk("Cna't register device Delete!\n");
	return 0;
}
//移除钩子和字符设备文件
void __exit removeFilter(void){
	nf_unregister_net_hook(&init_net, &myhook1);
	nf_unregister_net_hook(&init_net, &myhook2);
	unregister_chrdev(124, "inputRules");
	unregister_chrdev(125, "outputRules");
	unregister_chrdev(126, "Delete");
	printk("Remove Filter!\n");
}

module_init(registerFilter);
module_exit(removeFilter);
MODULE_AUTHOR("Lane Gong");
MODULE_LICENSE("GPL");
