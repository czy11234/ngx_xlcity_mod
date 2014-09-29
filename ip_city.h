#ifndef __IP_CITY_H__
#define __IP_CITY_H__
#include <stdint.h>
#include <vector>
#include <stdio.h>
using namespace std;

typedef struct ip_node_s{
	uint32_t begin;
	uint32_t end;
	char* province;
	char* city;
	char* isp;
}ip_node_t;

inline bool ip_node_cmp(const ip_node_t* a, const ip_node_t* b)
{
     return a->begin < b->begin;
}

int LoadIpInfo(const char* ipfile,vector<ip_node_t*>& ipnodes);

ip_node_t* FindIp(vector<ip_node_t*>& ipnodes, uint32_t ip);


#endif
