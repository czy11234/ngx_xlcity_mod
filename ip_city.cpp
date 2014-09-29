#include "ip_city.h"
#include "baselib.h"
#include <list>
#include <map>
#include <algorithm>

using namespace std;
#define memzero(buf,size) memset(buf,0,size)

static map<string,char*> provinces;
static map<string,char*> citys;
static map<string,char*> isps;
 	
static char* get_province_ptr(const char* province){
	map<string, char*>::iterator it;

	it = provinces.find(string(province));
	if(it == provinces.end()){//新的province
		int len = strlen(province)+1;
		char* p = (char*)malloc(len);
		memzero(p, len);
		strncpy(p, province, len);
		//LOG_DEBUG("province: [%s]", province);
		provinces.insert(make_pair(string(province), p));
		return p;
	}

	return it->second;
}
static char* get_city_ptr(const char* city){
	map<string, char*>::iterator it;

	it = citys.find(string(city));
	if(it == citys.end()){//新的city
		int len = strlen(city)+1;
		char* p = (char*)malloc(len);
		memzero(p, len);
		strncpy(p, city, len);
		citys.insert(make_pair(string(city), p));
		return p;
	}

	return it->second;
}

static char* get_isp_ptr(const char* isp){
	map<string, char*>::iterator it;

	it = isps.find(string(isp));
	if(it == isps.end()){//新的isp
		int len = strlen(isp)+1;
		char* p = (char*)malloc(len);
		memzero(p, len);
		strncpy(p, isp, len);
		isps.insert(make_pair(string(isp), p));
		return p;
	}

	return it->second;
}

/**
 * 所有字节都为数字返回1，否则返回0
 */
inline int is_digit(const char* str){
	for(unsigned i=0;str[i] != '\0';i++){
		if(!isdigit(str[i])){
			return 0;
		}
	}
	
	return 1;
}

int LoadIpInfo(const char* ipfile, vector<ip_node_t*>& ipnodes)
{
	//LOG_INFO("ipnodes: %d", ipnodes.size());
	int ret = 0;
	
	//char szbegin[16];
	//char szend[16];
	char szprovince[256];
	char szcity[256];
	char szisp[256];
	char szipbegin[32];
	char szipend[32];
	int n;


	list<string>::iterator it;
	list<string>* lines = new list<string>;

	ret = FileUtils::ReadLines(ipfile, *lines);
	if(ret != 0){
		delete lines;
		lines = NULL;
		LOG_ERROR("Read ip info from [%s] failed! ret=%d", ipfile, ret);
		return ret;
	}

	uint32_t ip_begin = 0;
	uint32_t ip_end = 0;
	char* province = NULL;
	char* city = NULL;
	char* isp = NULL;
	for(it=lines->begin();it!=lines->end();it++){
		string str = *it;
		ip_begin = ip_end = 0;
		memzero(szprovince,sizeof(szprovince));
		memzero(szcity,sizeof(szcity));
		memzero(szisp,sizeof(szisp));
		memzero(szipbegin,sizeof(szipbegin));
		memzero(szipend,sizeof(szipend));
		
		n = sscanf(str.c_str(), "%s %s %s %s %s", szipbegin,szipend,szprovince,szcity,szisp);
		if(n != 5){
			LOG_ERROR("Invalid Ip line [%s]", str.c_str());
			continue;
		}
		
		if(is_digit(szipbegin)){
			n = sscanf(szipbegin, "%u", &ip_begin);
			if(n != 1){
				LOG_ERROR("invalid begin ip [%s]", szipbegin);
				continue;
			}
		}else{//为点分十进制ip
			ip_begin = ip2long(szipbegin, strlen(szipbegin));
		}
		if(is_digit(szipend)){
			n = sscanf(szipend, "%u", &ip_end);
			if(n != 1){
				LOG_ERROR("invalid end ip [%s]", szipend);
				continue;
			}
		}else{//为点分十进制ip
			ip_end = ip2long(szipend, strlen(szipend));
		}
		//printf("ip [%u-%u] [%s.%s] [%s]\n", ip_begin, ip_end, szprovince, szcity, szisp);

		
		province = get_province_ptr(szprovince);
		city = get_city_ptr(szcity);
		isp = get_isp_ptr(szisp);
		
		
		ip_node_t* ip_node = (ip_node_t*)calloc(1, sizeof(ip_node_t));
		memzero(ip_node,sizeof(ip_node_t));
		ip_node->begin = ip_begin;
		ip_node->end = ip_end;
		ip_node->province = province;
		ip_node->city = city;
		ip_node->isp = isp;
		
		ipnodes.push_back(ip_node);
		
	}
	delete lines;
	lines = NULL;

	sort(ipnodes.begin(), ipnodes.end(), &ip_node_cmp);
	
	return 0;
}


ip_node_t* FindIp(vector<ip_node_t*>& ipnodes, uint32_t ip){
	int size = ipnodes.size();
	if(size < 1){
		return NULL;
	}
	int High = size - 1;

	int Low = 0;
	
	int M = size/2;

#define IP_EQ(ip, node) (ip>=node->begin && ip <=node->end)
	
	if(IP_EQ(ip, ipnodes[M]))
	{
		return ipnodes[M];
	}
	
	while(Low<=High)
	{
		if(High-Low<=1)
		{
			if(IP_EQ(ip, ipnodes[Low]))
			{
				return ipnodes[Low];
			}
			else if(IP_EQ(ip, ipnodes[High]))
			{
				return ipnodes[High];
			}
			else
			{
				return NULL;
			}
		}
		
		if(ip<ipnodes[M]->begin)
		{	
			High = M-1;
		}
		else if(ip>ipnodes[M]->end)
		{
			Low = M+1;
		}
		else if(IP_EQ(ip, ipnodes[M]))
		{
			return ipnodes[M];
		}

		M = (Low + High)/2;
	}

	return NULL;
}


inline ip_node_t* FindIp(vector<ip_node_t*>& ipnodes, const char* ip){
	uint32_t ip_n = ip2long(ip);
	return FindIp(ipnodes, ip_n);
}

#ifdef CITYTEST
#define IPFILE "/root/GDL/ngx_cdn_gdl/conf/xl-ips.txt"

int main(int argc,char* argv[]){
	//BlSetLogFile("stdout.txt", "stdout.debug");
	BlSetLogLevel(L_ALL);
	
	vector<ip_node_t*>* ipnodes = new vector<ip_node_t*>();
	int ret = LoadIpInfo(IPFILE,*ipnodes);
	if(ret != 0){
		LOG_ERROR("load ip failed!");
		return 1;
	}else{
		LOG_DEBUG("load ips : %d, citys:%d", ipnodes->size(), citys.size());
	}
	

	if(true){
		map<string,char*>::iterator it;
		for(it=provinces.begin();it!=provinces.end();it++){
			char* province = it->second;		
			LOG_INFO("province: %s", province);
		}

		for(it=isps.begin();it!=isps.end();it++){
			char* isp = it->second;		
			LOG_INFO("isp: %s", isp);
		}
		
	}


	#if 0
	int size = ipnodes->size();
	for(int i=0;i<100 && i < size;i++){
		ip_node_t* node = ipnodes->at(i);
		LOG_DEBUG("begin:%u, province:%s.%s isp:%s", node->begin, node->province, node->city,node->isp);
	}
	#endif
	
	while(1){
		printf("input ip:");
		char ip[32];
		memzero(ip,sizeof(ip));
		scanf("%s", ip);
		if(strcasecmp(ip, "exit")==0){
			break;
		}

		ip_node_t* node = FindIp(*ipnodes, ip);
		if(node == NULL){
			printf("ip [%s] not found!\n", ip);
		}else{
			printf("ip [%s] area: %s.%s ISP:%s \n", ip, node->province, node->city, node->isp);
		}
	}

	return 0;
}

#endif


