#include <stdio.h>
#include <stdlib.h>
//#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <queue>
#include <pthread.h>
extern "C"
{
#include <pcap.h>
}

using namespace std;

////////////////////////////////////////////////////////////////////////////
//基本信息格式，用于存入排列缓存队列中
struct PacketNode
{
	char CollectTime[25];
	char SrcMac[15];
	char DestMac[15];
	char SrcIP[15];
	char DestIP[15];
	int Type;
	int Length;
	int SrcPort;
	int DestPort;
};
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
//网络数据包格式，用于采集时，解析使用
typedef struct{    //定义以太帧的头部数据类型
	UCHAR DestMac[6];
	UCHAR SrcMac[6];
	UCHAR Etype[2];  
}ETHHEADER;
typedef struct  {   //IP头部的数据类型
        UCHAR  header_len:4;
        UCHAR  version:4;  
        UCHAR  tos:8;            // type of service
        USHORT  total_len:16;      // length of the packet
        USHORT  ident:16;          // unique identifier
        USHORT  flags:16;          
        UCHAR  ttl:8;            
        UCHAR  proto:8;          // protocol ( IP , TCP, UDP etc)
        USHORT  checksum:16;      
        UCHAR  sourceIP[4];
        UCHAR  destIP[4];
		        
}IPHEADER;
typedef struct {//定义端口数据类型用于解析TCP和UDP中的源端口和目的端口
	USHORT srcPort;
	USHORT decPort;
}PORT;

////////////////////////////////////////////////////////////////////////////
// 公共数据区　用于存储公共的信息数据
queue<PacketNode> g_qPacketNodes;    // 缓存队列
int g_bIsCapture = 0;                // 是否开启采集
int g_bIsFirstRun = 0;              // 是否已经第一次运行启动
int g_bIsWrite = 0;                  // 是否开启存储
long g_lCaptureNum = 0;             // 已采集到的记录数目
long g_lWriteNum = 0;             // 已写入的的记录数目
long g_lWriteFailNum = 0;          // 写入失败的次数

char g_dbName[30];                 // 数据表名
char g_tableName[30];
char g_strIP[15];
char g_strUser[50];
char g_strPass[20];
int g_nPort = 3306;


////////////////////////////////////////////////////////////
// 公开函数头信息

void Help();
// 采集的开启与关闭
void RunCapture();
void StopCapture();

// 存储的开启与关闭
void RunWrite();
void StopWrite();

// 状态查询
void ShowCaptureStatus();
void ShowWriteStatus();
void ShowStatus();

void InitDB();
void DBInfor();

// 三个线程
void* DBSwitchThread(void *threapara);
void* WriteThread(void *threapara);
void* CaptureThread(void *threapara);
void pcap_handle(u_char *user,const struct pcap_pkthdr *header, const u_char *pkt_data);

int GetCurTime(char *strTime,int type);
///////////////////////////////////////////////////////////

int main()
{
	printf("分布式数据包采集系统\n");
	char strTime[100];
	GetCurTime(strTime,0);
	printf("%s\n",strTime);
	InitDB();
	while(1)
	 {	 
		 printf("请输入命令:>");
		 char command[255];
	     gets(command);
	
		 if(strcmp(command,"run capture")==0)
		 {
			 RunCapture();
		 }
		 else if(strcmp(command,"stop capture")==0)
		 {
			 StopCapture();
		 }
		 else if(strcmp(command,"run write")==0)
		 {
			 RunWrite();
		 }
		 else if(strcmp(command,"stop write")==0)
		 {
			 StopWrite();
		 }
		 else if(strcmp(command,"status")==0)
		 {
			 ShowStatus();
		 }
		 else if(strcmp(command,"db status") == 0)
		 {
			 DBInfor();
		 }
		 else if(strcmp(command,"capture status")==0)
		 {
			 ShowCaptureStatus();
		 }
		 else if(strcmp(command,"write status")==0)
		 {
			 ShowWriteStatus();
		 }
		 else if(strcmp(command,"exit")==0)
		 {
			 exit(0);
		 }
		 else if(strcmp(command,"help") == 0)
		 {
			 Help();
		 }
		 else
		 {
			 printf("对不起，该命令不识别!!!\n");
		 }
	 }
	return 0;
}

void InitDB()
{
	strcpy(g_dbName,"packets_db");
	strcpy(g_strIP,"192.168.1.93");
	strcpy(g_strUser,"taylor");
	strcpy(g_strPass,"123456");
	strcpy(g_tableName,"2016_04_28");	

	// 启动数据库检测线程　
	pthread_t threadid;
	int temp = pthread_create(&threadid, NULL, DBSwitchThread, NULL);    
	if(temp < 0)
	{
		printf("数据库自动切换启动失败，请重启本程序 !!!!! \n");
		g_bIsWrite = 0;
		return ;
	}
}
void DBInfor()
{
	printf("---------数据库配置信息----------------\n");
	printf("%-12s %-12s\n","用户名",g_strUser);
	printf("%-12s %-12s\n","密码",g_strPass);
	printf("%-12s %-12s\n","IP",g_strIP);
	printf("%-12s %-12d\n","Port",g_nPort);
	printf("%-12s %-12s\n","数据库名",g_dbName);
	printf("%-12s %-12s\n","表名",g_tableName);
}
void Help()
{
	printf("==================================================================\n");
	printf("version：V1.0\n");
	printf("author：my2005lb\n\n\n");
	printf("%-12s %-12s\n","run capture","开启采集");
	printf("%-12s %-12s\n","stop capture","关闭采集");
	printf("%-12s %-12s\n","run write","开启存储");
	printf("%-12s %-12s\n","stop write","关闭存储");
	printf("%-12s %-12s\n","capture status","状态查询");
	printf("%-12s %-12s\n","write status","存储状态查询");
	printf("%-12s %-12s\n","db Status","数据库查看");
	printf("%-12s %-12s\n","exit","退出");
	printf("==================================================================\n");
}
// 采集的开启与关闭
void RunCapture()
{
	if(g_bIsCapture)
	{
		printf("当前采集已处于开启状态....\n");
	}
	else if(g_bIsFirstRun == 1)
	{
		g_bIsCapture = 1;
		printf("采集已启动....\n");
	}
	else
	{
		// 启动本线程
		g_bIsCapture = 1;
		pthread_t threadid;
		int temp = pthread_create(&threadid, NULL, CaptureThread, NULL);    
		if(temp < 0)
		{
			printf("开启采集失败，请重启本程序 !!!!! \n");
			return ;
		}
		//CaptureThread();
		printf("采集已开启....\n");
	}
}
void StopCapture()
{
	if(g_bIsCapture)
	{
		g_bIsCapture = 0;		
		printf("采集已关闭....\n");
	}
	else
	{
		printf("当前采集已处于关闭状态....\n");
	}
}

// 存储的开启与关闭
void RunWrite()
{
	if(g_bIsWrite)
	{
		printf("当前存储已处于开启状态....\n");
		return ;
	}
	else
	{
		g_bIsWrite = 1;
		// 启动本线程			
		pthread_t threadid;
		int temp = pthread_create(&threadid, NULL, WriteThread, NULL);    
		if(temp < 0)
		{
			printf("开启存储失败，请重启本程序 !!!!! \n");
			return ;
		}
	}
	printf("存储已开启....\n");
}
void StopWrite()
{
	if(g_bIsWrite)
	{
		g_bIsWrite = 0;		
		printf("存储已关闭....\n");
	}
	else
	{
		printf("当前存储已处于关闭状态....\n");
	}

}

// 状态查询
void ShowCaptureStatus()
{
	printf("===========采集运行查询==========\n");
	printf("采集状态：　　 %s\n",g_bIsCapture?"开启":"关闭");
	printf("已采集数据包： %ld\n",g_lCaptureNum);
}
void ShowWriteStatus()
{
	printf("===========存储运行查询==========\n");
	printf("存储状态：　　 %s\n",g_bIsWrite?"开启":"关闭");
	printf("已存储数据包： %ld\n",g_lWriteNum);
	printf("存储失败的次数： %ld\n",g_lWriteFailNum);
	
}
void ShowStatus()
{
	printf("===========系统运行状态==========\n");
	ShowCaptureStatus();
	printf("\n");
	ShowWriteStatus();
	printf("===========缓存队列查询==========\n");
	printf("缓存队列包数： %ld\n",g_qPacketNodes.size());
	printf("\n");

}
void* CaptureThread(void *threapara)
{
	char *device = "eth0";
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *phandle;
	if ((device = pcap_lookupdev(errbuf)) == NULL)
	{
		perror(errbuf);
		return 0;
	}
	
	phandle = pcap_open_live(device, 200, 0, 500, errbuf);
	if (phandle == NULL)
	{
		perror(errbuf);
		return 0;
	}
	g_bIsFirstRun = 1;
	g_bIsCapture = 1;
	pcap_loop(phandle, 0, pcap_handle, NULL);
}
void pcap_handle(u_char *user,const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	if(g_bIsCapture == 0)
		return ;

	ETHHEADER *eth_header = (ETHHEADER *)pkt_data;//解析数据包的以太帧头部
	g_lCaptureNum++;
	struct PacketNode node;
	node.Length = header->len;
	GetCurTime(node.CollectTime,1);
	if (header->len >= 14)// 解析数据包的IP头部
	{
	
		IPHEADER *ip_header=(IPHEADER *)(pkt_data+14);
		node.Type = ip_header->proto;
		sprintf(node.SrcMac,"%02X-%02X-%02X-%02X-%02X-%02X",eth_header->SrcMac[1], eth_header->SrcMac[2], eth_header->SrcMac[3],
			eth_header->SrcMac[4], eth_header->SrcMac[5]);
		sprintf(node.DestMac,"%02X-%02X-%02X-%02X-%02X-%02X",eth_header->DestMac[0],eth_header->DestMac[1], eth_header->DestMac[2],
			eth_header->DestMac[3],eth_header->DestMac[4], eth_header->DestMac[5]);
		sprintf(node.SrcIP,"%d.%d.%d.%d",ip_header->sourceIP[0] ,ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);
		sprintf(node.DestIP,"%d.%d.%d.%d",ip_header->destIP[0] ,ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);
		if(node.Type == 6 || node.Type == 17)
		{
			PORT *port=(PORT *)(pkt_data+14+20);
			node.SrcPort = ntohs(port->srcPort);
			node.DestPort = ntohs(port->decPort);
		}

		// 执行过滤操作，将与数据库交互的报文过滤掉
		if((strcmp(node.DestIP,g_strIP) == 0 || strcmp(node.SrcIP,g_strIP) == 0)
			&& (node.SrcPort == g_nPort || node.DestPort == g_nPort))
			return ;

		g_qPacketNodes.push(node);
	}
}

void* WriteThread(void *threapara)
{		
	MYSQL* pMyData;       //msyql 连接句柄
	pMyData = mysql_init(NULL);
	if(mysql_real_connect(pMyData,g_strIP,g_strUser,g_strPass,g_dbName,g_nPort,NULL,0))
	{
		if ( mysql_select_db( pMyData, g_dbName) < 0 ) //选择制定的数据库失败
		{
			g_bIsWrite = 0;
			mysql_close( pMyData ) ;		
			printf("没有所选的数据库\n");
			return 0 ;
		}
		else
		{
			printf("已连到上数据库...\n");			
		}
	}
	else
    {  
		g_bIsWrite = 0;
		DBInfor();
        mysql_close( pMyData ) ;//初始化mysql结构失败	
		printf("数据库连接失败，请确认选项\n");
        return 0 ;
    }
	while(g_bIsWrite)
	{
		if(g_qPacketNodes.size() > 0)
		{
			struct PacketNode node = g_qPacketNodes.front();
			g_qPacketNodes.pop();

			// 获得队头结点，构造SQL语句，写入数据库中
			char strSQL[500];
			sprintf(strSQL,"insert into %s (CollectTime,DestIP,DestMac,DestPort,Length,SrcIP,SrcMac,SrcPort,PacketType) values ('%s','%s','%s',%d,%d,'%s','%s',%d,%d)",
				g_tableName,node.CollectTime,node.DestIP,node.DestMac,node.DestPort,node.Length,node.SrcIP,node.SrcMac,node.SrcPort,node.Type);

			if(!mysql_real_query( pMyData, strSQL,strlen(strSQL)))
				g_lWriteNum++;
			else
			{
				g_lWriteFailNum++;
				//printf("Error :%s\n",strSQL);
			}
				
		}
	}
	mysql_close( pMyData );
	pthread_exit(NULL);
}

// 用于数据库的动态切换，在后台每隔几秒，查询当前的时间是否满足切换
void* DBSwitchThread(void *threapara)
{
	MYSQL* pMyData;       //msyql 连接句柄
	pMyData = mysql_init(NULL);
	if(mysql_real_connect(pMyData,g_strIP,g_strUser,g_strPass,g_dbName,g_nPort,NULL,0))
	{
		if ( mysql_select_db( pMyData, g_dbName) < 0 ) //选择制定的数据库失败
		{
			mysql_close( pMyData ) ;		
			printf("数据库切换启动失败.....[选择数据库失败]\n");
			return 0 ;
		}
		else
		{
			printf("数据库切换已启动...\n");			
		}
	}
	else
    {  
        mysql_close( pMyData ) ;//初始化mysql结构失败	
		printf("数据库切换启动失败...[数据库连接失败]\n");
        return 0 ;
    }

	while(1)
	{
		char strTime[20];
		GetCurTime(strTime,2);
		if(strcmp(strTime,g_tableName) != 0)
		{
			char strSQL[300];
			char strCreateTime[30];
			GetCurTime(strCreateTime,1);
			//写入数据库中的主控表，同时创建新表
			
			
			sprintf(strSQL,"insert into manager_table (CreateTime,TableName) values ('%s','%s')",strCreateTime,strTime);
			if(!mysql_real_query( pMyData, strSQL,strlen(strSQL)))
			{
				printf("创建新节点成功 [%s]\n",strTime);
			}
			else
				printf("Error :%s\n",strSQL);
			
			sprintf(strSQL,"create table %s (id int auto_increment not null primary key,CollectTime datetime,",strTime);
			sprintf(strSQL,"%sDestIP varchar(15) not null,DestMac  varchar(15) not null,DestPort int not null,",strSQL);
			sprintf(strSQL,"%sLength int not null,SrcIP varchar(15) not null,SrcMac varchar(15) not null,SrcPort int not null,",strSQL);
			sprintf(strSQL,"%sPacketType int not null)",strSQL);
			
			if(!mysql_real_query( pMyData, strSQL,strlen(strSQL)))
			{
				printf("创建新表成功 [%s]\n",strTime);
			}
			else
				printf("Error :%s\n",strSQL);				
			strcpy(g_tableName,strTime);
		}
		sleep(5);
	}
	mysql_close( pMyData);
	pthread_exit(NULL);
}
int GetCurTime(char *strTime,int type)
{
    time_t t;
	struct tm *tm = NULL;
    t = time(NULL);
    if(t == -1)
	{
        return -1;
    }
    tm = localtime(&t);
    if(tm == NULL)
	{
        return -1;
    }
	if(type == 0)
		sprintf(strTime,"系统运行时间为: %d-%d-%d %d:%d:%d\n",tm->tm_year + 1900,tm->tm_mon + 1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec);
	else if(type == 1)
		sprintf(strTime,"%d-%d-%d %d:%d:%d",tm->tm_year + 1900,tm->tm_mon + 1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec);
	else if(type == 2)
		sprintf(strTime,"%d_%d_%d",tm->tm_year + 1900,tm->tm_mon + 1,tm->tm_mday);

    return 0;
}
