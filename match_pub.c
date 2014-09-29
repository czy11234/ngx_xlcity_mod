//#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ngx_pub.h"
#include "match_pub.h"

static ngx_http_regex_t * __ngx_regex_compile(ngx_location_ctx_t  *locctx, ngx_regex_compile_t *rc)
{
	//u_char                     *p;
	//size_t                      size;
	ngx_http_regex_t           *re;

	rc->pool = locctx->pool;

	if (ngx_regex_compile(rc) != NGX_OK) {
		CONF_ERROR(locctx->log, "invalid regex [%V], err: %V", &rc->pattern,  &rc->err);
		return NULL;
	}else{
		//CONF_DEBUG(locctx->log, "compile regex[%V] Success!", &rc->pattern);
	}

	re = ngx_pcalloc(locctx->pool, sizeof(ngx_http_regex_t));
	if (re == NULL) {
		return NULL;
	}

	re->regex = rc->regex;
	re->ncaptures = rc->captures;
	re->name = rc->pattern;
	
	return re;
}


static ngx_int_t __ngx_regex_match(ngx_http_regex_t *re, ngx_str_t *s)
{
    ngx_int_t                   rc;

    rc = ngx_regex_exec(re->regex, s,  0, 0);
    //printf("match_pub_regex(%.*s=>%.*s)=%d\n", re->name.len,re->name.data,  s->len, s->data, rc);
	
    if (rc == NGX_REGEX_NO_MATCHED) {
        return NGX_DECLINED;
    }

    return rc < 0? NGX_ERROR:NGX_OK;
}

static ngx_int_t __ngx_regex_location_init(ngx_location_ctx_t  *locctx,
					ngx_location_t *loc, ngx_str_t *regex, ngx_uint_t caseless)
{
	ngx_regex_compile_t  rc;
	u_char               errstr[NGX_MAX_CONF_ERRSTR];

	ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

	//这里的regex必须以\0结束，不然pcre库可能会出错，导致匹配不上。
	//所以后面申请的空间加1了，并且使用memzero设置为0了。
	rc.pattern.len = regex->len;
	rc.pattern.data = ngx_palloc(locctx->pool,  rc.pattern.len+1);
	ngx_memzero(rc.pattern.data, rc.pattern.len+1);
	ngx_memcpy(rc.pattern.data, regex->data, regex->len);
	//rc.pattern = *regex;
	
	rc.err.len = NGX_MAX_CONF_ERRSTR;
	rc.err.data = errstr;

#if (NGX_HAVE_CASELESS_FILESYSTEM)
	rc.options = NGX_REGEX_CASELESS;
#else
	rc.options = caseless;
#endif

	loc->regex = __ngx_regex_compile(locctx, &rc);
	if (loc->regex == NULL) {
	    return NGX_ERROR;
	}

	loc->name = *regex;

	return NGX_OK;
}

static ngx_int_t __ngx_add_loc(ngx_location_ctx_t* locctx, 
		ngx_queue_t **locations,   ngx_location_t *loc)
{
    ngx_location_queue_t  *lq;

    if (*locations == NULL) {
        *locations = ngx_palloc(locctx->pool,
                                sizeof(ngx_location_queue_t));
        if (*locations == NULL) {
            return NGX_ERROR;
        }

        ngx_queue_init(*locations);
    }

    lq = ngx_palloc(locctx->pool, sizeof(ngx_location_queue_t));
    if (lq == NULL) {
        return NGX_ERROR;
    }

    if (loc->exact_match
        || loc->regex)
    {
        lq->exact = loc;
        lq->inclusive = NULL;
	//CONF_INFO(locctx->log, "add [%V] to exact", &loc->name);
    } else {
        lq->exact = NULL;
        lq->inclusive = loc;
	//CONF_INFO(locctx->log, "add [%V] to inclusive", &loc->name);
    }

    lq->name = &loc->name;
    //lq->file_name = cf->conf_file->file.name.data;
    //lq->line = cf->conf_file->line;
    //CONF_ERROR(locctx->log, "loc->name: %V",  &loc->name);
	
    ngx_queue_init(&lq->list);

    ngx_queue_insert_tail(*locations, &lq->queue);

    return NGX_OK;
}

static ngx_int_t __ngx_cmp_locations(const ngx_queue_t *one, const ngx_queue_t *two)
{
    ngx_int_t                   rc;
    ngx_location_t   *first, *second;
    ngx_location_queue_t  *lq1, *lq2;

    lq1 = (ngx_location_queue_t *) one;
    lq2 = (ngx_location_queue_t *) two;

    first = lq1->exact ? lq1->exact : lq1->inclusive;
    second = lq2->exact ? lq2->exact : lq2->inclusive;
 
    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }


    rc = ngx_strcmp(first->name.data, second->name.data);

    if (rc == 0 && !first->exact_match && second->exact_match) {
        /* an exact match must be before the same inclusive one */
        return 1;
    }

    return rc;
}

/**
 * 合并重复的location 
 */
static ngx_int_t
__ngx_join_exact_locations(ngx_location_ctx_t* locctx, ngx_queue_t *locations)
{
    ngx_queue_t                *q, *x;
    ngx_location_queue_t  *lq, *lx;

    q = ngx_queue_head(locations);

    while (q != ngx_queue_last(locations)) {

        x = ngx_queue_next(q);
        lq = (ngx_location_queue_t *) q;
        lx = (ngx_location_queue_t *) x;
        //CONF_INFO(cf->log, " lq->name: %V", lq->name);
        if (ngx_strcmp(lq->name->data, lx->name->data) == 0) {

            if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
                LOG_ERROR(locctx->log, "duplicate location \"%V\" ", lx->name);

                return NGX_ERROR;
            }

            lq->inclusive = lx->inclusive;

            ngx_queue_remove(x);

            continue;
        }

        q = ngx_queue_next(q);
    }

    return NGX_OK;
}


static void
__ngx_create_locations_list(ngx_queue_t *locations, ngx_queue_t *q)
{
    u_char                     *name;
    size_t                      len;
    ngx_queue_t                *x, tail;
    ngx_location_queue_t  *lq, *lx;

    if (q == ngx_queue_last(locations)) {
        return;
    }

    lq = (ngx_location_queue_t *) q;

    if (lq->inclusive == NULL) {
        __ngx_create_locations_list(locations, ngx_queue_next(q));
        return;
    }

    len = lq->name->len;
    name = lq->name->data;

    for (x = ngx_queue_next(q);
         x != ngx_queue_sentinel(locations);
         x = ngx_queue_next(x))
    {
        lx = (ngx_location_queue_t *) x;

        if (len > lx->name->len
            || (ngx_strncmp(name, lx->name->data, len) != 0))
        {
            break;
        }
    }

    q = ngx_queue_next(q);

    if (q == x) {
        __ngx_create_locations_list(locations, x);
        return;
    }

    ngx_queue_split(locations, q, &tail);
    ngx_queue_add(&lq->list, &tail);

    if (x == ngx_queue_sentinel(locations)) {
        __ngx_create_locations_list(&lq->list, ngx_queue_head(&lq->list));
        return;
    }

    ngx_queue_split(&lq->list, x, &tail);
    ngx_queue_add(locations, &tail);

    __ngx_create_locations_list(&lq->list, ngx_queue_head(&lq->list));

    __ngx_create_locations_list(locations, x);
}


/*
 * to keep cache locality for left leaf nodes, allocate nodes in following
 * order: node, left subtree, right subtree, inclusive subtree
 */

static ngx_location_tree_node_t *
__ngx_create_locations_tree(ngx_location_ctx_t* locctx, ngx_queue_t *locations,
    size_t prefix)
{
    size_t                          len;
    ngx_queue_t                    *q, tail;
    ngx_location_queue_t      *lq;
    ngx_location_tree_node_t  *node;

    q = ngx_queue_middle(locations);

    lq = (ngx_location_queue_t *) q;
    len = lq->name->len - prefix;

    node = ngx_palloc(locctx->pool,
                      offsetof(ngx_location_tree_node_t, name) + len);
    if (node == NULL) {
        return NULL;
    }

    node->left = NULL;
    node->right = NULL;
    node->tree = NULL;
    node->exact = lq->exact;
    node->inclusive = lq->inclusive;

    node->len = (u_char) len;
    ngx_memcpy(node->name, &lq->name->data[prefix], len);

    ngx_queue_split(locations, q, &tail);

    if (ngx_queue_empty(locations)) {
        /*
         * ngx_queue_split() insures that if left part is empty,
         * then right one is empty too
         */
        goto inclusive;
    }

    node->left = __ngx_create_locations_tree(locctx, locations, prefix);
    if (node->left == NULL) {
        return NULL;
    }

    ngx_queue_remove(q);

    if (ngx_queue_empty(&tail)) {
        goto inclusive;
    }

    node->right = __ngx_create_locations_tree(locctx, &tail, prefix);
    if (node->right == NULL) {
        return NULL;
    }

inclusive:

    if (ngx_queue_empty(&lq->list)) {
        return node;
    }

    node->tree = __ngx_create_locations_tree(locctx, &lq->list, prefix + len);
    if (node->tree == NULL) {
        return NULL;
    }

    return node;
}

/*
 * NGX_OK       - exact match
 * NGX_AGAIN    - inclusive match
 * NGX_DECLINED - no match
 */

static ngx_int_t
__ngx_core_find_static_loc(ngx_location_tree_node_t *node,
						ngx_location_match_ctx_t* match_ctx)
{
    u_char     *uri;
    size_t      len, n;
    ngx_int_t   rc, rv;

    len = match_ctx->uri->len;
    uri = match_ctx->uri->data;

    rv = NGX_DECLINED;

    for ( ;; ) {
        if (node == NULL) {
            return rv;
        }

        //ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        //               "test location: \"%*s\"", node->len, node->name);

        n = (len <= (size_t) node->len) ? len : node->len;

        rc = ngx_filename_cmp(uri, node->name, n);

        if (rc != 0) {
            node = (rc < 0) ? node->left : node->right;

            continue;
        }

        if (len > (size_t) node->len) {

            if (node->inclusive) {

                match_ctx->loc  = node->inclusive;
                rv = NGX_AGAIN;

                node = node->tree;
                uri += n;
                len -= n;

                continue;
            }

            /* exact only */

            node = node->right;

            continue;
        }

        if (len == (size_t) node->len) {
            if (node->exact) {
                match_ctx->loc = node->exact;
                return NGX_OK;
            } else {
                match_ctx->loc = node->inclusive;
                return NGX_AGAIN;
            }
        }

        node = node->left;
    }
}


ngx_int_t __ngx_init_static_location_trees(ngx_location_ctx_t* locctx)
{
    ngx_queue_t        *locations;
    //ngx_location_t   *clcf;
    //ngx_location_queue_t  *lq;

    locations = locctx->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    if (ngx_queue_empty(locations)) {
        return NGX_OK;
    }

/*
    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_location_queue_t *) q;

        clcf = lq->exact ? lq->exact : lq->inclusive;

        if (ngx_http_init_static_location_trees(cf, clcf) != NGX_OK) {
            return NGX_ERROR;
        }
    }
**/
    if (__ngx_join_exact_locations(locctx, locations) != NGX_OK) {
        return NGX_ERROR;
    }

    __ngx_create_locations_list(locations, ngx_queue_head(locations));

    locctx->static_locations = __ngx_create_locations_tree(locctx, locations, 0);
    if (locctx->static_locations == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/**
 * type,	ngx_type,	说明
 *   =  		=	精确匹配
 * 	b		^~   匹配前缀(在正则之前)
 *   r		~	区分大小写的正则匹配
 *   R		~*   不区分大小写的正则匹配
 *   e		     匹配前缀(在正则之后)
 */
ngx_int_t ngx_location_add(
		ngx_location_ctx_t  *locctx, ngx_location_info_t* locinfo){
	ngx_uint_t rc;
	ngx_location_t* location;
	location = ngx_pcalloc(locctx->pool, sizeof(ngx_location_t));
	
	switch(locinfo->type){
	case '=':
		location->exact_match = 1;
	break;
	case 'b':
		location->noregex = 1;
	break;
	case 'r':
		rc =  __ngx_regex_location_init(locctx, location, &locinfo->url, 0);
		if(rc != NGX_OK){
			ngx_pfree(locctx->pool, location);
			CONF_ERROR(locctx->log, "regex_location_init(%V,0) failed!", &locinfo->url);
			return rc;
		}
	break;
	case 'R':
		rc = __ngx_regex_location_init(locctx,location, &locinfo->url, 1);
		if(rc != NGX_OK){
			ngx_pfree(locctx->pool, location);
			CONF_ERROR(locctx->log, "regex_location_init(%V,1) failed!", &locinfo->url);
			return rc;
		}
	break;
	case 'e':
		//nothing todo..
	break;
	}
	location->name = locinfo->url;
	location->permission = locinfo->perm;
	location->urlid = locinfo->urlid;
	
	//LOG_INFO(locctx->log, "############ %V ############", &locinfo->url);
	if (__ngx_add_loc(locctx, &locctx->locations, location) != NGX_OK) {
		CONF_ERROR(locctx->log, "ngx_http_add_loc(%V) failed!", &locinfo->url);
		return NGX_ERROR;
	}

	return NGX_OK;
}



ngx_int_t ngx_location_ctx_init(ngx_location_ctx_t* locctx)
{
    ngx_uint_t                   n;
    ngx_queue_t                 *q, *locations, tail;
    ngx_location_t    *loc;
    ngx_location_queue_t   *lq;
    ngx_location_t   **locarr;
    ngx_uint_t                   r;
    ngx_queue_t                 *regex;

    locations = locctx->locations;

    if (locations == NULL) {
        return NGX_OK;
    }

    ngx_queue_sort(locations, __ngx_cmp_locations);

    n = 0;
    regex = NULL;
    r = 0;

    for (q = ngx_queue_head(locations);
         q != ngx_queue_sentinel(locations);
         q = ngx_queue_next(q))
    {
        lq = (ngx_location_queue_t *) q;

        loc = lq->exact ? lq->exact : lq->inclusive;

        if (loc->regex) {
            r++;

            if (regex == NULL) {
                regex = q;
            }

            continue;
        }
    }

    if (q != ngx_queue_sentinel(locations)) {
        ngx_queue_split(locations, q, &tail);
    }

    if (regex) {
        locarr = ngx_palloc(locctx->pool, (r + 1) * sizeof(ngx_location_t **));
        if (locarr == NULL) {
            return NGX_ERROR;
        }

        locctx->regex_locations = locarr;

        for (q = regex;
             q != ngx_queue_sentinel(locations);
             q = ngx_queue_next(q))
        {
            lq = (ngx_location_queue_t *) q;
            *(locarr++) = lq->exact;
	   //printf("match_pub exact:%.*s\n", lq->exact->name.len, lq->exact->name.data);
        }

        *locarr = NULL;

        ngx_queue_split(locations, regex, &tail);
    }

    ngx_int_t rc = __ngx_init_static_location_trees(locctx);

    return rc;
}

/*
 * NGX_OK       - exact or regex match
 * NGX_ERROR    - regex error
 * NGX_DECLINED - no match
 */

ngx_int_t ngx_location_match(
			ngx_location_ctx_t* locctx, 
			ngx_location_match_ctx_t* match_ctx)
{
	ngx_int_t                  rc;

	ngx_int_t                  n;
	ngx_uint_t                 noregex = 0;
	ngx_location_t  **ploc;

	rc = __ngx_core_find_static_loc(locctx->static_locations, match_ctx);
	if (rc == NGX_OK) {
		return rc;
	}

	if (rc == NGX_AGAIN) {
		noregex = match_ctx->loc->noregex;
		rc = NGX_OK;
	}

	if (noregex == 0 && locctx->regex_locations) {
		for (ploc = locctx->regex_locations; *ploc; ploc++) {
			//ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			//               "test location: ~ \"%V\"", &(*clcfp)->name);
			//LOG_INFO(match_ctx->log, "Test location [%V] ",  &(*ploc)->name);
			n = __ngx_regex_match( (*ploc)->regex, match_ctx->uri);

			if (n == NGX_OK) {
				match_ctx->loc = *ploc;
				return NGX_OK;
			}else if (n == NGX_DECLINED) {
				continue;
			}

			return NGX_ERROR;
		}
	}

	return rc;
}

char *ngx_conf_set_loc_array_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char  *p = (char*)conf;
	ngx_location_info_t* loc;
	ngx_str_t         *value;
	ngx_array_t      **a;
	ngx_conf_post_t   *post;
	u_char type;

	a = (ngx_array_t **) (p + cmd->offset);

	value = (ngx_str_t*)cf->args->elts;

	if(value[1].len != 1){
            	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid type value \"%s\"", value[1].data);
		return (char*)NGX_CONF_ERROR;
	}
	type = value[1].data[0];
	if(type != '=' && type != 'b' && type != 'r' && type != 'R' && type != 'e'){
            	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid type value \"%c\", invalid value[=brRe]", type);
		return (char*)NGX_CONF_ERROR;
	}
	
	if (*a == NGX_CONF_UNSET_PTR) {
		*a = ngx_array_create(cf->pool, 4, sizeof(ngx_location_info_t));
		if (*a == NULL) {
		    return (char*)NGX_CONF_ERROR;
		}
	}

	loc = (ngx_location_info_t*)ngx_array_push(*a);
	if (loc == NULL) {
		return (char*)NGX_CONF_ERROR;
	}

	//*s = value[1];
	loc->type = type;
	loc->url = value[2];
	
	if (cmd->post) {
		post = (ngx_conf_post_t*)cmd->post;
		return post->post_handler(cf, post, loc);
	}

	return NGX_CONF_OK;
}

