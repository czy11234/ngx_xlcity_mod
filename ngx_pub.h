#ifndef __NGX_PUB_CITY_H__
#define __NGX_PUB_CITY_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>

#define clog connection->log
#define LOG_ERROR(log, fmt, args...) ngx_log_error(NGX_LOG_ERR, log, 0, fmt, ##args)
#define LOG_INFO(log, fmt, args...) ngx_log_error(NGX_LOG_INFO, log, 0,fmt, ##args)
#define LOG_DEBUG(log, fmt, args...) ngx_log_error(NGX_LOG_DEBUG, log, 0, fmt, ##args)


#define CONF_ERROR(log, format, args...); \
	{ u_char buf[1024*2]; ngx_memzero(buf,sizeof(buf)); \
	ngx_sprintf(buf, "ERROR:"format"\n",##args);printf((const char*)buf);} \
	LOG_ERROR(log, format,##args);

#define CONF_INFO(log, format, args...); \
	{ u_char buf[1024*2]; ngx_memzero(buf,sizeof(buf)); \
	ngx_sprintf(buf, "INFO:"format"\n",##args);printf((const char*)buf);} \
	LOG_INFO(log, format,##args);

#define CONF_DEBUG(log, format, args...); \
	{ u_char buf[1024*2]; ngx_memzero(buf,sizeof(buf)); \
	ngx_sprintf(buf, "DEBUG:"format"\n",##args);printf((const char*)buf);} \
	LOG_DEBUG(log, format,##args);

#define ngx_pcalloc_obj(pool, type) (type*)ngx_pcalloc(pool, sizeof(type))

#endif
