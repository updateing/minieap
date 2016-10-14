/* -*- Mode: C; tab-width: 4; -*- */
/*
* 文件名称：logging.h
* 摘	要：MiniEAP日志功能
* 作	者：updateing@HUST
* 邮	箱：haotia@gmail.com
*/

#ifndef _LOGGING_H
#define _LOGGING_H

#include <string.h>
#include <errno.h>

#ifdef DEBUG
#define FUNC_NAME __func__
#else
#define FUNC_NAME ""
#endif

#define PR_ERRNO(desc) \
    PR_ERR(desc ": %s (%d)",  strerror(errno), errno);

#define PR_ERR(...) \
    print_log("E", FUNC_NAME, __VA_ARGS__);

#define PR_WARN(...) \
    print_log("W", FUNC_NAME, __VA_ARGS__);
    
#define PR_INFO(...) \
    print_log("I", FUNC_NAME, __VA_ARGS__);
    
#define PR_DBG(...) \
    print_log("D", FUNC_NAME, __VA_ARGS__);

typedef enum _LOG_DESTINATION {
	LOG_TO_FILE,
	LOG_TO_CONSOLE
} LOG_DEST;

void set_log_destination(LOG_DEST dst);
void print_log_raw(const char* log_format, ...);
void print_log(const char* log_level, const char* func, const char* log_format, ...);

#endif
