extern "C" {
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_pub.h"
#include <nginx.h>
#include "match_pub.h"
}
#define LOG_SHORT_PREFIX 1
#include "baselib.h"
#include "ip_city.h"

#define XFWD_NEW_VER 1003013

typedef struct {
	ngx_flag_t enable;
	ngx_flag_t ip_from_url; //用于测试，表示可以从url中取得IP参数。
	ngx_flag_t ip_from_head; //表示从head中取地址，用于前端有代理时。(x_real_ip,x_forwarded_for)
	ngx_flag_t param_in_head; //城市相关参数从自定义头中传递(默认从get参数中传递)
	ngx_str_t ip_file;  //迅雷IP文件。
	ngx_array_t* url_list;		//需要进行IP=>地址的URL列表。
	ngx_location_ctx_t* proc_url_ctx;
	vector<ip_node_t*>* ip_nodes;
#if (nginx_version>XFWD_NEW_VER)
    ngx_array_t       *proxies;     /* array of ngx_cidr_t */
    ngx_flag_t         proxies_recursive;
#endif
} ngx_http_ip_city_srv_conf_t;

#if nginx_version>XFWD_NEW_VER  
static char *ngx_http_ip_city_proxies(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#endif
static ngx_int_t ngx_http_ip_city_mod_init(ngx_conf_t *cf);

static void *ngx_http_ip_city_create_srv_conf(ngx_conf_t *cf);
static  char *ngx_http_ip_city_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t  ngx_http_ip_city_init_process(ngx_cycle_t *cycle);

static ngx_command_t  ngx_http_ip_city_commands[] = {
    { ngx_string("ip_city"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ip_city_srv_conf_t, enable),
      NULL },
    { ngx_string("ip_from_url"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ip_city_srv_conf_t, ip_from_url),
      NULL },
    { ngx_string("ip_from_head"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ip_city_srv_conf_t, ip_from_head),
      NULL },
    { ngx_string("ip_file"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ip_city_srv_conf_t, ip_file),
      NULL },
    { ngx_string("proc_url"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_loc_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ip_city_srv_conf_t, url_list),
      NULL },
#if nginx_version>XFWD_NEW_VER  
    { ngx_string("proxies"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_ip_city_proxies,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ip_city_srv_conf_t, proxies),
      NULL },

    { ngx_string("proxies_recursive"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ip_city_srv_conf_t, proxies_recursive),
      NULL },
#endif
	ngx_null_command
};

static ngx_http_module_t  ngx_http_ip_city_module_ctx = {
    NULL,                          /* preconfiguration */
    &ngx_http_ip_city_mod_init,        /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,  						   /* init main configuration */

    ngx_http_ip_city_create_srv_conf,     /* create server configuration */
    ngx_http_ip_city_merge_srv_conf,     /* merge server configuration */

    NULL,  /* create location configuration */
    NULL /* merge location configuration */
};


ngx_module_t  ngx_http_ip_city_module = {
    NGX_MODULE_V1,
    &ngx_http_ip_city_module_ctx, /* module context */
    ngx_http_ip_city_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    &ngx_http_ip_city_init_process,          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,      /* exit process */
    NULL,      /* exit master */
    NGX_MODULE_V1_PADDING
};

//在原来参数之后再添加一个参数。
ngx_int_t ngx_http_common_add_args(ngx_http_request_t* r, ngx_str_t* args){
	if(r->args.len < 1){
		r->args = *args;
	}else{
		ngx_str_t new_args;
		new_args.data = (u_char*)ngx_palloc(r->pool, r->args.len+args->len+4);
		new_args.len = ngx_sprintf(new_args.data, "%V&%V", &r->args, args)-new_args.data;
		r->args = new_args;
	}
	r->valid_unparsed_uri = 0;
	
	return 0;
}

inline  ngx_int_t ngx_http_ip_city_add_header_in(ngx_http_request_t *r, 
		ngx_str_t* key, ngx_str_t *value)
{
    ngx_table_elt_t  *h;
	ngx_uint_t hash;
	unsigned n;
	u_char ch;
    if (value->len) {
        h = (ngx_table_elt_t*)ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->key = *key;
        h->value = *value;
        h->lowcase_key = (u_char*)ngx_pcalloc(r->pool, key->len+1);
        
        hash = 0;
        for (n = 0; n < key->len; n++) {
            ch = key->data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            hash = ngx_hash(hash, ch);
            h->lowcase_key[n] = ch;
        }
        h->hash = hash; //ngx_hash_key(key->data, key->len);

    }

    return NGX_OK;
}


inline ngx_int_t ngx_http_ip_city_return(ngx_http_request_t *r, uint32_t userid){
	u_char args_sid[32];
	int len = 0;
	ngx_memzero(args_sid,32);
	len = ngx_sprintf(args_sid, "uid=%d", userid)-args_sid;
	ngx_str_t args = {len, args_sid};
	ngx_http_common_add_args(r, &args);
	return NGX_OK;
}

ngx_uint_t ngx_http_get_remote_ip(ngx_http_request_t *r){
	ngx_http_ip_city_srv_conf_t *conf = NULL;
	conf = (ngx_http_ip_city_srv_conf_t*)ngx_http_get_module_srv_conf(
				r, ngx_http_ip_city_module);
	uint32_t ip = 0;
	//LOG_INFO(r->clog, "ip_from_url:%d,ip_from_head:%d, real_ip:%P, forwarded_for:%P", 
	//			conf->ip_from_url, conf->ip_from_head,r->headers_in.x_real_ip,r->headers_in.x_forwarded_for);
	do{
		ngx_str_t* real_ip;
		
		if(conf->ip_from_url){
			//用于测试，从URL中获取IP信息。
			ngx_str_t szip = ngx_null_string;
			if(ngx_http_arg(r, (u_char*)"ip", 2, &szip)==NGX_OK){
				ip = ip2long((const char*)szip.data, szip.len);
				break;
			}
		}

		if(conf->ip_from_head){
			if(r->headers_in.x_real_ip != NULL){
				//LOG_INFO(r->clog, "x_real_ip: %V=%V", &r->headers_in.x_real_ip->key, &r->headers_in.x_real_ip->value);
				real_ip = &r->headers_in.x_real_ip->value;
				ip = ip2long((const char*)real_ip->data, real_ip->len);
				break;
			}
		
			//ngx_str_t x_real_ip = ngx_null_string;

			// TODO: 这里要查明哪个版本开始变化的。
#if nginx_version>XFWD_NEW_VER	
			ngx_array_t* xfwd = &r->headers_in.x_forwarded_for;
		    if (xfwd->nelts > 0 && conf->proxies != NULL) {
				ngx_addr_t addr;
				memset(&addr,0,sizeof(addr));
			    addr.sockaddr = r->connection->sockaddr;
			    addr.socklen = r->connection->socklen;
			    
		        (void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL,
		                                           conf->proxies, conf->proxies_recursive);
		        struct sockaddr_in * sin = (struct sockaddr_in *) addr.sockaddr;
				ip =  ntohl(sin->sin_addr.s_addr);
				break;
		    }
#else
			if(r->headers_in.x_forwarded_for != NULL){
				real_ip = &r->headers_in.x_forwarded_for->value;
				unsigned i=0;
				for(i=0;i<real_ip->len;i++){
					if(real_ip->data[i] == (u_char)','){
						break;
					}
				}
				real_ip->len = i;
				//LOG_INFO(r->clog, "x_forwarded_for: %V=%V", &r->headers_in.x_forwarded_for->key, real_ip);
				
				ip = ip2long((const char*)real_ip->data, real_ip->len);
				break;
			}
#endif
		}
		
		struct sockaddr_in * sin = (struct sockaddr_in *)r->connection->sockaddr;
		ip =  ntohl(sin->sin_addr.s_addr);
	}while(0);

	return ip;
}

ngx_int_t ngx_http_ip_city_handler(ngx_http_request_t *r)
{
	ngx_int_t     rc = NGX_OK;
	ngx_http_ip_city_srv_conf_t *conf = NULL;
	conf = (ngx_http_ip_city_srv_conf_t*)ngx_http_get_module_srv_conf(
				r, ngx_http_ip_city_module);
	LOG_INFO(r->clog, "############### Req [%V] ############", &r->uri);
	if(conf == NULL || !conf->enable){
		return rc;
	}

	ngx_location_match_ctx_t locctx;
	memset(&locctx,0,sizeof(locctx));
	locctx.uri = &r->uri;
	locctx.log = r->connection->log;
	
	rc  = ngx_location_match(conf->proc_url_ctx, &locctx);
	if( rc != NGX_OK){//没匹配到,直接返回。
		LOG_INFO(r->clog, "url [%V] Not matched!", &r->uri);
		return NGX_OK;
	}

	//需要根据IP,查出城市.
	uint32_t remote_ip = ngx_http_get_remote_ip(r);
	char* szip = (char*)ngx_pcalloc(r->pool, 32);
	ngx_memzero(szip, 32);
	long2ip(remote_ip,szip);

	static ngx_str_t x_province_key = ngx_string("x-province");
	static ngx_str_t x_city_key = ngx_string("x-city");
	static ngx_str_t x_isp_key = ngx_string("x-isp");
	static ngx_str_t x_ip_key = ngx_string("x-ip");
	
	ip_node_t* node = FindIp(*conf->ip_nodes, remote_ip);
	if(node != NULL){
		LOG_INFO(r->clog, "Find ip [%s] info [%s.%s %s]", szip, node->province, node->city, node->isp);

		//LOG_INFO(r->clog, "r->proxy:%d", r->proxy);

		if(conf->param_in_head){//从定义头中传递参数。
			
			ngx_str_t x_province_value = {strlen(node->province), (u_char*)node->province};
			ngx_str_t x_city_value = {strlen(node->city), (u_char*)node->city};
			ngx_str_t x_isp_value = {strlen(node->isp), (u_char*)node->isp};
			ngx_str_t x_ip_value = {strlen(szip), (u_char*)szip};
			/**
			ngx_str_t x_province_value = ngx_string("province");
			ngx_str_t x_city_value = ngx_string("city");
			ngx_str_t x_isp_value = ngx_string("isp");
			ngx_str_t x_ip_value = ngx_string("ip");
			**/
			ngx_http_ip_city_add_header_in(r, &x_province_key, &x_province_value);
			ngx_http_ip_city_add_header_in(r, &x_city_key, &x_city_value);
			ngx_http_ip_city_add_header_in(r, &x_isp_key, &x_isp_value);			
			ngx_http_ip_city_add_header_in(r, &x_ip_key, &x_ip_value);			
			
		}else{
			ngx_str_t args;
			int args_len = strlen(node->province)+strlen(node->city)+strlen(node->isp);
			args.data = (u_char*)ngx_pcalloc(r->pool, args_len+32);
			args.len = ngx_sprintf(args.data, "province=%s&city=%s&isp=%s", 
							node->province, node->city, node->isp)-args.data;
			ngx_http_common_add_args(r, &args);
		}
		//LOG_INFO(r->clog, "new args: %V", &r->args);
	}else{
		//没有找到相应的IP段，不添加参数。
		LOG_INFO(r->clog, "Ip [%s] not found!", szip);
		if(conf->param_in_head){//从定义头中传递参数。
			static ngx_str_t x_isp_value = ngx_string("unknow");
			ngx_str_t x_ip_value = {strlen(szip), (u_char*)szip};		
			ngx_http_ip_city_add_header_in(r, &x_isp_key, &x_isp_value);	
			ngx_http_ip_city_add_header_in(r, &x_ip_key, &x_ip_value);
		}
	}

	return NGX_OK;
	
}

static ngx_int_t ngx_http_ip_city_mod_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = (ngx_http_core_main_conf_t*)ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = (ngx_http_handler_pt*)ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	if (h == NULL) {
	    return NGX_ERROR;
	}
	
	*h = ngx_http_ip_city_handler;

	return NGX_OK;
}


void *ngx_http_ip_city_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_ip_city_srv_conf_t  *conf;

	conf = (ngx_http_ip_city_srv_conf_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_ip_city_srv_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}
	conf->enable = NGX_CONF_UNSET;
	conf->ip_from_url = NGX_CONF_UNSET;
	conf->ip_from_head = NGX_CONF_UNSET;
	conf->param_in_head = NGX_CONF_UNSET;
	conf->url_list = (ngx_array_t*)NGX_CONF_UNSET_PTR;
#if nginx_version>XFWD_NEW_VER  
	conf->proxies = (ngx_array_t*)NGX_CONF_UNSET;
	conf->proxies_recursive = NGX_CONF_UNSET;
#endif
	return conf;
}

#define NGX_CONF_UNSET_PROXY    ((ngx_array_t*)NGX_CONF_UNSET)


#define ngx_conf_merge_proxies(conf, prev, default)            \
    if (conf == NGX_CONF_UNSET_PROXY) {                                            \
        conf = (prev == NGX_CONF_UNSET_PROXY) ? default : prev;                    \
    }


static  char *ngx_http_ip_city_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child){
	ngx_http_ip_city_srv_conf_t *prev = (ngx_http_ip_city_srv_conf_t*)parent;
	ngx_http_ip_city_srv_conf_t *conf = (ngx_http_ip_city_srv_conf_t*)child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	ngx_conf_merge_value(conf->ip_from_url, prev->ip_from_url, 0);
	ngx_conf_merge_value(conf->ip_from_head, prev->ip_from_head, 0);
	ngx_conf_merge_value(conf->param_in_head, prev->param_in_head, 1);
	ngx_conf_merge_str_value(conf->ip_file, prev->ip_file, "conf/xl-ips.txt");
	#if nginx_version>XFWD_NEW_VER 
		ngx_conf_merge_proxies(conf->proxies, prev->proxies, (ngx_array_t*)NULL);
		ngx_conf_merge_value(conf->proxies_recursive, prev->proxies_recursive, 1);
	#endif
	if ( conf->enable == 1){
		cf->cycle->conf_ctx[ngx_http_ip_city_module.index] = (void***)conf;
		unsigned int i;
		ngx_int_t rc;
		CONF_DEBUG(cf->cycle->log,"############ init proc_url_ctx ###############");
		conf->proc_url_ctx = ngx_pcalloc_obj(cf->cycle->pool, ngx_location_ctx_t);
		conf->proc_url_ctx->pool = cf->cycle->pool;
		conf->proc_url_ctx->log = cf->cycle->log;
		
		if(conf->url_list != NGX_CONF_UNSET_PTR){
			CONF_DEBUG(cf->cycle->log,"############ ngx_location_add ###############");
			ngx_location_info_t* locinfos = (ngx_location_info_t*)conf->url_list->elts;
			for(i=0; i< conf->url_list->nelts; i++){
				ngx_location_info_t* locinfo = &locinfos[i];
				rc = ngx_location_add(conf->proc_url_ctx, locinfo);
				if(rc != NGX_OK){
					CONF_ERROR(cf->cycle->log, "add url [%V]  to proc list failed!", &locinfo->url);
					return (char*)NGX_CONF_ERROR;
				}else{
					CONF_INFO(cf->cycle->log, "add url [%V] to proc list success!", &locinfo->url);
				}
			}
		}
		rc = ngx_location_ctx_init(conf->proc_url_ctx);
		if(rc != NGX_OK){
			CONF_ERROR(cf->cycle->log, "location ctx init failed!!");
			return (char*)NGX_CONF_ERROR;
		}

		conf->ip_nodes = new vector<ip_node_t*>();
		
		ngx_conf_full_name(cf->cycle, &conf->ip_file, 0);		
		rc = LoadIpInfo((const char*)conf->ip_file.data, *conf->ip_nodes);
		if(rc != 0){
			CONF_ERROR(cf->cycle->log, "load ip file from [%V] failed!", &conf->ip_file);
			return (char*)NGX_CONF_ERROR;
		}else{
			printf("load %d ip from [%.*s]\n", (int)conf->ip_nodes->size(), 
						(int)conf->ip_file.len, (char*)conf->ip_file.data);
		}
		
	}
	
	return NGX_CONF_OK;
}

ngx_int_t  ngx_http_ip_city_init_process(ngx_cycle_t *cycle)
{
	printf("process [%d] inited!\n", ngx_getpid());

	return 0;
}

void ngx_http_ip_city_exit_process(ngx_cycle_t* cycle)
{
	ngx_http_ip_city_srv_conf_t* srv_conf = NULL;
	srv_conf = (ngx_http_ip_city_srv_conf_t*)cycle->conf_ctx[ngx_http_ip_city_module.index];
	if(srv_conf == NULL){
		printf("srv_conf is null\n");
		return;
	}

	if(srv_conf->ip_nodes != NULL){
		vector<ip_node_t*>* ip_nodes = srv_conf->ip_nodes;
		for(size_t i=0;i<ip_nodes->size();i++){
			ip_node_t* ip_node = ip_nodes->at(i);
			if(ip_node != NULL){
				free(ip_node);
			}
		}
		delete ip_nodes;
		srv_conf->ip_nodes = NULL;
	}
}

#if nginx_version>XFWD_NEW_VER  
static char *ngx_http_ip_city_proxies(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char  *p = (char*)conf;
    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t              *cidr;

    value = (ngx_str_t*)cf->args->elts;
    
	ngx_array_t      **a;
	a = (ngx_array_t **) (p + cmd->offset);

	if (*a == NGX_CONF_UNSET_PTR) {
		*a = ngx_array_create(cf->pool, 2, sizeof(ngx_cidr_t));
		if (*a == NULL) {
		    return (char*)NGX_CONF_ERROR;
		}
	}

	cidr = (ngx_cidr_t*)ngx_array_push(*a);
	if (cidr == NULL) {
		return (char*)NGX_CONF_ERROR;
	}

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
         cidr->family = AF_UNIX;
         return (char *)NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return (char *)NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    return (char *)NGX_CONF_OK;
}
#endif
