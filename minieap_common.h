#ifndef _MINIEAP_MINIEAP_COMMON_H
#define _MINIEAP_MINIEAP_COMMON_H

typedef enum _function_result {
    SUCCESS = 0,
    FAILURE = -1
} RESULT;

#define IS_FAIL(x) ((x) == FAILURE)
#endif
