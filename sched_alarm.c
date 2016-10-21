#include "minieap_common.h"
#include "linkedlist.h"
#include "logging.h"
#include "misc.h"
#include "sched_alarm.h"

#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <malloc.h>

typedef struct _alarm_event {
    int remaining;
    int id;
    void (*func)(void*);
    void* user;
} ALARM_EVENT;

static LIST_ELEMENT* g_alarm_list = NULL;
static int g_last_id = 0;

static int alarm_event_id_node_cmpfunc(void* id, void* node) {
    if (*(int*)id == ((ALARM_EVENT*)node)->id) {
        return 0;
    }
    return 1;
}

static int find_min_remaining(LIST_ELEMENT* list) {
    LIST_ELEMENT* _curr;
    int _min = INT_MAX;

    for (_curr = list; _curr; _curr = _curr->next) {
        if (((ALARM_EVENT*)_curr->content)->remaining < _min) {
            _min = ((ALARM_EVENT*)_curr->content)->remaining;
        }
    }

    return _min;
}

static void update_remaining_and_fire_single(void* alarm_event, void* secs) {
#define EVENT ((ALARM_EVENT*)alarm_event)
    EVENT->remaining -= *(int*)secs;
    if (EVENT->remaining <= 0) {
        EVENT->func(EVENT->user);
        unschedule_alarm(EVENT->id);
    }
}

static void update_remaining_and_fire(LIST_ELEMENT* alarm_list, int secs_elapsed_since_last_update) {
    list_traverse(alarm_list, update_remaining_and_fire_single, &secs_elapsed_since_last_update);
}

void alarm_sig_handler(int sig) {
    int _curr_remaining = alarm(0);
    update_remaining_and_fire(g_alarm_list, _curr_remaining);
}

RESULT sched_alarm_init() {
    signal(SIGALRM, alarm_sig_handler);
    return SUCCESS;
}

void sched_alarm_destroy() {
    list_destroy(&g_alarm_list, TRUE);
    alarm(0);
}

void unschedule_alarm(int id) {
    remove_data(&g_alarm_list, &id, alarm_event_id_node_cmpfunc, TRUE);
}

int schedule_alarm(int secs, void (*func)(void*), void* user) {
    ALARM_EVENT* _event = (ALARM_EVENT*)malloc(sizeof(ALARM_EVENT));
    if (_event < 0) {
        PR_ERR("无法为闹钟事件分配内存");
        return -1;
    }
    _event->remaining = secs;
    _event->id = ++g_last_id;
    _event->func = func;
    _event->user = user;

    int _curr_remaining = alarm(0);
    update_remaining_and_fire(g_alarm_list, _curr_remaining);
    int _curr_min = find_min_remaining(g_alarm_list);

    if (_curr_min > secs) {
        /* The new event is nearest */
        alarm(secs);
    }

    insert_data(&g_alarm_list, _event);

    return _event->id;
}
