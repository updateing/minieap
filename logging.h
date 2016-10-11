/* -*- Mode: C; tab-width: 4; -*- */
/*
* 文件名称：logging.h
* 摘	要：MiniEAP日志功能
* 作	者：updateing@HUST
* 邮	箱：haotia@gmail.com
*/

#ifndef _LOGGING_H
#define _LOGGING_H

typedef enum _LOG_DESTINATION {
	LOG_TO_FILE,
	LOG_TO_CONSOLE
} LOG_DEST;

void set_log_destination(LOG_DEST dst);
void print_log(const char* log_format, ...);
void print_log_raw(const char* log_format, ...);

#endif
