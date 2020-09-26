#ifndef _MINIEAP_MINIEAP_COMMON_H
#define _MINIEAP_MINIEAP_COMMON_H

#define VERSION "0.93"

typedef enum _function_result {
    SUCCESS = 0,
    FAILURE = -1
} RESULT;

#define IS_FAIL(x) ((x) == FAILURE)

/* Line buffer length when reading files */
#define MAX_LINE_LEN 100

/* Max path length */
#define MAX_PATH 260

#define TRUE 1
#define FALSE 0

#endif
