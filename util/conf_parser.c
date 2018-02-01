/*
 * MiniEAP configuration file parser
 *
 * Configuration file consists of lines in the following format:
 *  KEY=VALUE
 * Comment lines must begin with #
 * No inline comments allowed.
 * Leading spaces are ignored.
 * Multiple entries with same key are ALLOWED. (e.g. module=rjv3 module=printer)
 *
 * The parser will create a linked list for each key-value pair
 * in the file.
 */

#include <linkedlist.h>
#include <minieap_common.h>
#include <conf_parser.h>
#include <logging.h>
#include <misc.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * There won't be many config entries,
 * no need to use complex structure here.
 */
static LIST_ELEMENT* g_conf_list;
static const char* g_conf_file;

/*
 * Find 1st non-space char, modify ptr if found
 */
#define LTRIM(start, ptr, maxlen) \
	do { \
		for (ptr = start; ptr < start + maxlen && isspace(*ptr); ptr++); \
	} while (0);

/*
 * Trim trailing spaces.
 * Will modify original string.
 */
#define RTRIM(start, maxlen) \
	do { \
		char* tmp; \
		int actual_len = strnlen(start, maxlen); \
		for (tmp = start + actual_len - 1; tmp >= start && isspace(*tmp); tmp--); \
		if (isspace(*(tmp + 1))) *(tmp + 1) = 0; \
	} while (0);

#define TO_CONFIG_PAIR(x) ((CONFIG_PAIR*)x)

void conf_parser_set_file_path(const char* path) {
	g_conf_file = path;
}

RESULT conf_parser_add_value(const char* key, const char* value) {
	if (!(key && value)) {
		return FAILURE;
	}

	CONFIG_PAIR* pair = (CONFIG_PAIR*)malloc(sizeof(CONFIG_PAIR));
	if (pair == NULL) {
		PR_ERRNO("无法为新的配置项分配内存空间");
		return FAILURE;
	}
	pair->key = strdup(key);
	pair->value = strdup(value);
	insert_data(&g_conf_list, pair);

	return SUCCESS;
}

RESULT conf_parser_parse_now() {
	if (!g_conf_file) {
		return FAILURE;
	}

	FILE* fp = fopen(g_conf_file, "r");
	if (fp == NULL) {
		PR_ERRNO("无法打开配置文件");
		return FAILURE;
	}

	char line_buf[MAX_LINE_LEN + 1] = {0};
	char* start_pos;
	char* delim_pos;
	while (fgets(line_buf, MAX_LINE_LEN, fp)) {
		int line_len = strnlen(line_buf, MAX_LINE_LEN);
		LTRIM(line_buf, start_pos, line_len);
		if (*start_pos == '#') {
			continue;
		}
		delim_pos = strchr(start_pos, '=');
		if (delim_pos != NULL) {
			RTRIM(delim_pos, line_len - (delim_pos - line_buf));
			*delim_pos = 0; /* strtok lol (do this before RTRIM, otherwise strnlen fails) */
			if (IS_FAIL(conf_parser_add_value(start_pos, delim_pos + 1))) {
				fclose(fp);
				return FAILURE;
			}
		} else {
			PR_WARN("配置文件行格式错误：%s", line_buf);
		}
	}

	fclose(fp);
	return SUCCESS;
}

static RESULT conf_pair_key_cmpfunc(void* to_find, void* node) {
	return strcmp((char*)to_find, TO_CONFIG_PAIR(node)->key);
}

RESULT conf_parser_get_value(const char* key, char* buf, int buflen) {
	if (!(key && buf)) {
		return FAILURE;
	}

	CONFIG_PAIR* pair = lookup_data(g_conf_list, (void*)key, conf_pair_key_cmpfunc);
	if (!pair) {
		return FAILURE;
	}

	if (strlen(pair->value) >= buflen) {
		return FAILURE;
	}

	strcpy(buf, pair->value);
	return SUCCESS;
}

RESULT conf_parser_set_value(const char* key, const char* value) {
	if (!(key && value)) {
		return FAILURE;
	}

	CONFIG_PAIR* pair = lookup_data(g_conf_list, (void*)key, conf_pair_key_cmpfunc);
	if (pair) {
		chk_free((void**)&pair->value);
		pair->value = strdup(value);
		return SUCCESS;
	} else {
		return conf_parser_add_value(key, value);
	}
}

void conf_parser_traverse(void (*func)(CONFIG_PAIR*, void*), void* user) {
	list_traverse(g_conf_list, (void (*)(void*, void*))func, user);
}

static void conf_write_one_pair(void* node, void* fp) {
	fprintf((FILE*)fp, "%s=%s\n", TO_CONFIG_PAIR(node)->key, TO_CONFIG_PAIR(node)->value);
}

RESULT conf_parser_save_file() {
	if (!g_conf_list) {
		return FAILURE;
	}

	FILE* fp = fopen(g_conf_file, "w");
	if (fp == NULL) {
		PR_ERRNO("无法打开配置文件");
		return FAILURE;
	}

	list_traverse(g_conf_list, conf_write_one_pair, fp);
	fclose(fp);
	return SUCCESS;
}

static void conf_free_one_pair(void* node, void* unused) {
	chk_free((void**)&TO_CONFIG_PAIR(node)->key);
	chk_free((void**)&TO_CONFIG_PAIR(node)->value);
}

void conf_parser_free() {
	list_traverse(g_conf_list, conf_free_one_pair, NULL);
	list_destroy(&g_conf_list, TRUE);
}
