#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_variables.h>

typedef struct ngx_location_tree_node_s ngx_location_tree_node_t;

/**
 * type,	ngx_type,	说明
 *   =  		=	精确匹配
 * 	b		^~   匹配前缀(在正则之前)
 *   r		~	区分大小写的正则匹配
 *   R		~*   不区分大小写的正则匹配
 *   e		     匹配前缀(在正则之后)
 */
typedef struct {
	ngx_int_t   urlid;
	char type;   
	ngx_str_t url;
	ngx_str_t perm; //权限。
}ngx_location_info_t;

typedef struct  {
	ngx_str_t     name;          /* location name */
	ngx_http_regex_t  *regex;
	ngx_str_t		permission;
	ngx_int_t   	urlid;
	unsigned      exact_match:1; //精确匹配
	unsigned      noregex:1; //在正则之前
}ngx_location_t;
//ngx_http_core_loc_conf_s

typedef struct {
	ngx_location_t       **regex_locations;
	ngx_location_tree_node_t   *static_locations;
	ngx_queue_t  *locations;
	ngx_pool_t* 	pool;
	ngx_log_t* 	log;
}ngx_location_ctx_t;


typedef struct {
    ngx_queue_t                      queue;
    ngx_location_t        *exact;
    ngx_location_t        *inclusive;
    ngx_str_t                       *name;
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_location_queue_t;
//ngx_location_queue_t

struct ngx_location_tree_node_s {
    ngx_location_tree_node_t   *left;
    ngx_location_tree_node_t   *right;
    ngx_location_tree_node_t   *tree;

    ngx_location_t        *exact;
    ngx_location_t        *inclusive;

    u_char                           len;
    u_char                           name[1];
};

typedef struct {
	ngx_location_t* loc;
	ngx_log_t* log;
	ngx_str_t*  uri;
}ngx_location_match_ctx_t;

ngx_int_t ngx_location_add(
		ngx_location_ctx_t  *locctx,  ngx_location_info_t* locinfo);
ngx_int_t ngx_location_ctx_init(ngx_location_ctx_t* loc_ctx);

ngx_int_t ngx_location_match(
			ngx_location_ctx_t* loc_ctx, 
			ngx_location_match_ctx_t* match_ctx);


char *ngx_conf_set_loc_array_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
