#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#define MAX_RULES_NUM 5

#define TCP 10
#define UDP 11
#define ICMP 12
#define ANY 0
#define INPUT 1
#define OUTPUT 2
//getopt参数
extern int optind, opterr, optopt;
extern char *optarg;

char input_rules[100];//5*20
char output_rules[100];//5*20
char temp[100];
char choice[1];
int in_num = 0;
int out_num = 0;


struct Rule{//20Bytes
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int src_addr;
	unsigned int dst_addr;
	unsigned int protocol;
}rulesList[MAX_RULES_NUM];

//规则转字符串流
void ruleToString(struct Rule onerule, char* rules_pointer){
	*(int *)rules_pointer = onerule.src_port;
	*(int *)(rules_pointer + 4) = onerule.dst_port;
	*(int *)(rules_pointer + 8) = onerule.src_addr;
	*(int *)(rules_pointer + 12) = onerule.dst_addr;
	*(int *)(rules_pointer + 16) = onerule.protocol;
}
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
//展示规则
void display(int nums, int flag, struct Rule *list){
	char *name = flag==1 ? "INPUT" : "OUTPUT";
	int i;
	char *protocol;
	char ip[16];
	unsigned int temp;
	printf("%s CHAIN\n", name);
	printf("-------------------------------------------------------------------------\n");
	printf("PROTOCOL\tSRC_ADDR\tDST_ADDR\tSRC_PORT\tDST_PORT\n");
	for(i=0;i<nums;i++){
		if(list[i].protocol == 10)
			protocol = "TCP";
		else if(list[i].protocol == 11)
			protocol = "UDP"; 
		else if(list[i].protocol == 12)
			protocol = "ICMP";
		else
			protocol = "*";
		printf("%s\t\t",protocol);
		if(list[i].src_addr == 0)
			printf("*\t\t");
		else{
			temp = list[i].src_addr;
			sprintf(ip,"%d.%d.%d.%d",temp&0xff,(temp>>8)&0xff,(temp>>16)&0xff,(temp>>24)&0xff);
			printf("%s\t\t",ip);
		}
		if(list[i].dst_addr == 0)
			printf("*\t\t");
		else{
			temp = list[i].dst_addr;
			sprintf(ip,"%d.%d.%d.%d",temp&0xff,(temp>>8)&0xff,(temp>>16)&0xff,(temp>>24)&0xff);
			printf("%s\t\t",ip);
		}
		if(list[i].src_port == 0)
			printf("*\t\t");
		else
			printf("%d\t\t",list[i].src_port);
		if(list[i].dst_port == 0)
			printf("*\n");
		else
			printf("%d\n",list[i].dst_port);
	}
}
//帮助文档
void help(){
	printf("----------Command Line Parameters----------\n");
	printf("1. -l: View the current firewall rules(INPUT/OUTPUT)\n");
	printf("2. -A: Append firewall rules to specified chain\n");
	printf("\t 2.1 -p: protocol(TCP, UDP, etc)\n");
	printf("\t 2.2 -s: source IP address\n");
	printf("\t 2.3 -d: destination IP address\n");
	printf("\t 2.4 -m: source port\n");
	printf("\t 2.5 -n: destination port\n");
	printf("3. -F: Delete firewall rules(INPUT/OUTPUT)\n");
	printf("4. -h: Help\n");
}


int main(int argc, char **argv){
	int chain=0,state,flag=1,is_delete;
	int fp,count=0,i;
	struct Rule onerule = {0,0,0,0,0};
	
	
	while(EOF != (state = getopt(argc,argv,"l:A:p:s:d:m:n:F:h"))){//读取参数
		switch(state){//匹配每个选项
			case 'l'://-l 查看当前规则
				if(!strcmp(optarg,"INPUT")){//INPUT链
					fp = open("/dev/inputRules",O_RDWR,S_IRUSR|S_IWUSR);//打开设备文件
					if(fp>0){
						count = read(fp,input_rules,100);//read系统调用，数据读入input_rules,返回值是规则数量
						for(i=0;i<count;i++){
							onerule = stringToRule(input_rules+i*20);
							rulesList[i] = onerule;
						}//处理成规则列表
						display(count,1,rulesList);//命令行输出
					}else{
						printf("Error!Can't open device inputRules.\n");
					}
				}else{//同理
					fp = open("/dev/outputRules",O_RDWR,S_IRUSR|S_IWUSR);
					if(fp>0){
						count = read(fp,output_rules,100);
						for(i=0;i<count;i++){
							onerule = stringToRule(output_rules+i*20);
							rulesList[i] = onerule;
						}
						display(count,2,rulesList);
					}else{
						printf("Error!Can't open device outputRules.\n");
					}
				}
				break;
			case 'A':
				if(!strcmp(optarg,"INPUT"))
					chain = INPUT;
				else
					chain = OUTPUT;
				break;
			case 'p'://配置协议
				if(!strcmp(optarg,"UDP"))
					onerule.protocol = UDP;
				else if(!strcmp(optarg,"TCP"))
					onerule.protocol = TCP;
				else if(!strcmp(optarg,"ICMP"))
					onerule.protocol = ICMP;
				else
					onerule.protocol = ANY;
				break;
			case 's'://源ip
				if(inet_aton(optarg,(struct in_addr*)&onerule.src_addr)==0){
					flag = 0;
					printf("Invalid source IP address!\n");
				}
				break;
			case 'd'://目的ip
				if(inet_aton(optarg,(struct in_addr*)&onerule.dst_addr)==0){
					flag = 0;
					printf("Invalid destination IP address!\n");
				}
				break;
			case 'm'://源端口
				onerule.src_port = atoi(optarg);
				break;
			case 'n'://目的端口
				onerule.dst_port = atoi(optarg);
				break;
			case 'F':
				fp = open("/dev/Delete",O_RDWR,S_IRUSR|S_IWUSR);//打开设备
				if(fp>0){
					if(!strcmp(optarg,"INPUT")){//删除INPUT链
						choice[0]='1';
						is_delete = write(fp,choice,1);//调用write系统调用
						if(is_delete)//删除成功
							printf("Delete Successfully!\n");
						else//删除失败
							printf("Delete Unsuccessfully.\n");
					}else{//同理
						choice[0]='2';
						is_delete = write(fp,choice,1);
						if(is_delete)
							printf("Delete Successfully!\n");
						else
							printf("Delete Unsuccessfully.\n");
					}
				}else{
					printf("Error!Can't open device Delete.\n");
				}
				break;
			case 'h':
				help();
				break;
			case '?':
				printf("Unknown Option!\n");
				break;
			default:
				break;
			
		}
	}
	if(chain == 0)//不是要写规则，结束
		return 0;
	if(flag==0){//ip出错，不能写入
		printf("Rule entry failed.Please try again!\n");
		return 0;
	}else{//向内核写规则
		if(chain==1){
			//read rule nums.
			fp = open("/dev/inputRules",O_RDWR,S_IRUSR|S_IWUSR);
			if(fp>0){
				count = read(fp, temp, 100);//这一步只是为了读数量，确保不超5条
				if(count==5){
					printf("ERROR:The number of rule has already reached the upper limit!\n");
					return 0;
				}
				ruleToString(onerule, input_rules);//规则转流
				count = write(fp,input_rules,20);//写入
				printf("INPUT CHAIN(%d/5): Rule is accepted successfully! You can type '-l INPUT' to view details.\n", count);
			}else{
				printf("Error!Can't open device inputRules.\n");
			}
		}else{//同理
			// read rule nums.
			fp = open("/dev/outputRules",O_RDWR,S_IRUSR|S_IWUSR);
			if(fp>0){
				count = read(fp, temp, 100);
				if(count==5){
					printf("ERROR:The number of rule has already reached the upper limit!\n");
					return 0;
				}
				ruleToString(onerule, output_rules);
				count = write(fp,output_rules,20);
				printf("OUTPUT CHAIN(%d/5): Rule is accepted successfully! You can type '-l OUTPUT' to view details.\n", count);
			}else{
				printf("Error!Can't open device outputRules.\n");
			}
		}
	}
	//printf("%d\n", *((int *)rules));
	return 0;
}
