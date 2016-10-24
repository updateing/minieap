/* -*- Mode: C; tab-width: 4; -*- */
/*
* 文件名称：logging.c
* 摘	要：MiniEAP日志功能
* 作	者：updateing@HUST
* 邮	箱：haotia@gmail.com
*/

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "logging.h"

#define LOG_FORMAT_BUFFER_SIZE 1024
#define DEFAULT_LOG_FILE "/tmp/minieap.log"

static char g_time_buffer[20]; // Buffer for time output
static char* g_log_path = DEFAULT_LOG_FILE; // Log file path
static FILE* g_log_fp = NULL; // Log destination
static LOG_DEST g_dest = LOG_TO_CONSOLE;

static char* get_formatted_date() {
	time_t time_tmp;
	struct tm* time_s;

	time(&time_tmp);
	time_s = localtime(&time_tmp);

	sprintf(g_time_buffer, "%d/%d/%d %d:%02d:%02d", time_s->tm_year + 1900, time_s->tm_mon + 1,
				time_s->tm_mday, time_s->tm_hour, time_s->tm_min, time_s->tm_sec);
	return g_time_buffer;
}

/*
 * 打印一行文本
 */
static void print_raw_line(FILE* log_file, const char* log_format, va_list argptr) {
	if (log_file == NULL) {
		fprintf(stderr, "Internal error: Log destination is not set, printing to stdout!\n");
		log_file = stdout;
	}
	vfprintf(log_file, log_format, argptr);
}

/*
 * 打印一行日志并附加时间与调用点信息
 */
static void print_detail_line(FILE* log_file, const char* log_level,
                      const char* func_name, const char* log_format, va_list argptr) {
	char format_buffer[LOG_FORMAT_BUFFER_SIZE];
    int _strlen;

    if (func_name != NULL && func_name[0] != 0) {
	    snprintf(format_buffer, LOG_FORMAT_BUFFER_SIZE, "[%s][%s](%s) %s",
	            get_formatted_date(), log_level, func_name, log_format);
	} else {
	    snprintf(format_buffer, LOG_FORMAT_BUFFER_SIZE, "[%s][%s] %s",
	             get_formatted_date(), log_level, log_format);
	}

	/* Append a newline if not exist */
	_strlen = strlen(format_buffer);
	if (format_buffer[_strlen - 1] != '\n') {
	    format_buffer[_strlen] = '\n';
	    format_buffer[_strlen + 1] = 0;
	}

	print_raw_line(log_file, format_buffer, argptr);
}

/*
 * 设置日志的目标，是打印到标准输出还是写入文件
 *
 * 注：写入文件时，将直接打开文件来写入，而不是reopen stdout到文件。
 * 故仍可以使用printf来直接打印到控制台（用户交互使用）
 */
void set_log_destination(LOG_DEST dst) {
    g_dest = dst;
}

/*
 * 按之前的目标设置来打印一行日志
 */
void print_log(const char* log_level, const char* func_name, const char* log_format, ...) {
	va_list argptr;

	va_start(argptr, log_format);
	print_detail_line(g_log_fp, log_level, func_name, log_format, argptr);
	va_end(argptr);
}

/*
 * 按之前的目标设置来打印一行文本，不添加时间标记
 */
void print_log_raw(const char* log_format, ...) {
	va_list argptr;

	va_start(argptr, log_format);
	print_raw_line(g_log_fp, log_format, argptr);
	va_end(argptr);
}

void start_log() {
	switch (g_dest) {
		case LOG_TO_CONSOLE:
			g_log_fp = stdout;
			break;
		case LOG_TO_FILE:
			g_log_fp = fopen(g_log_path, "a");
			if (g_log_fp == NULL) {
			    g_log_fp = stdout;
			    g_dest = LOG_TO_CONSOLE;
			    PR_ERRNO("日志文件打开失败，将输出至控制台");
			}
			setvbuf(g_log_fp, NULL, _IOLBF, BUFSIZ);
			break;
	}
}

void close_log() {
    if (g_dest == LOG_TO_FILE)
        fclose(g_log_fp);
}

void set_log_file_path(char* path) {
    g_log_path = path;
}
