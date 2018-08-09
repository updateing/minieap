#include <sys/file.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "minieap_common.h"
#include "logging.h"
#include "config.h"
#include "misc.h"

#define PID_STRING_BUFFER_SIZE 12
#define PID_FILE_NONE "none"

static int pid_lock_fd = 0; // 0 = uninitialized, -1 = disabled

RESULT pid_lock_init(const char* pidfile) {
    if (pidfile == NULL) {
        return FAILURE;
    }

    if (strcmp(pidfile, PID_FILE_NONE) == 0) {
        PR_WARN("PID 检查已禁用，请确保一个接口上只有一个认证进程")
        pid_lock_fd = -1;
        return SUCCESS;
    }

    pid_lock_fd = open(pidfile, O_RDWR | O_CREAT, 0644);
    if (pid_lock_fd < 0) {
        PR_ERRNO("无法打开 PID 文件");
        return FAILURE;
    }
    return SUCCESS;
}

// Return SUCCESS: We handled the incident and are ready to proceed (i.e. only when user asked)
// Return FAILURE: We could not handle, or we do not want to proceed
static RESULT pid_lock_handle_multiple_instance() {
    char readbuf[PID_STRING_BUFFER_SIZE]; // 12 is big enough to hold PID number

    if (read(pid_lock_fd, readbuf, PID_STRING_BUFFER_SIZE) < 0 || readbuf[0] == '\0') {
        PR_ERRNO("已有另一个 MiniEAP 进程正在运行但 PID 未知，请手动结束其他 MiniEAP 进程");
        return FAILURE;
    } else {
        int pid = atoi(readbuf);
        switch (get_program_config()->kill_type) {
            case KILL_NONE:
                PR_ERR("已有另一个 MiniEAP 进程正在运行，PID 为 %d", pid);
                return FAILURE;
            case KILL_ONLY:
                PR_ERR("已有另一个 MiniEAP 进程正在运行，PID 为 %d，即将发送终止信号并退出……", pid);
                kill(pid, SIGTERM);
                return FAILURE;
            case KILL_AND_START:
                PR_WARN("已有另一个 MiniEAP 进程正在运行，PID 为 %d，将在发送终止信号后继续……", pid);
                kill(pid, SIGTERM);
                return SUCCESS;
            default:
                PR_ERR("-k 参数未知");
                return FAILURE;
        }
    }
}

RESULT pid_lock_save_pid() {
    if (pid_lock_fd == 0) {
        PR_WARN("PID 文件尚未初始化");
        return FAILURE;
    } else if (pid_lock_fd < 0) {
        // User disabled pid lock
        return SUCCESS;
    }

    char writebuf[PID_STRING_BUFFER_SIZE];

    my_itoa(getpid(), writebuf, 10);

    if (write(pid_lock_fd, writebuf, strnlen(writebuf, PID_STRING_BUFFER_SIZE)) < 0) {
        PR_ERRNO("无法将 PID 保存到 PID 文件");
        return FAILURE;
    }

    return SUCCESS;
}

RESULT pid_lock_lock() {
    if (pid_lock_fd == 0) {
        PR_WARN("PID 文件尚未初始化");
        return FAILURE;
    } else if (pid_lock_fd < 0) {
        // User disabled pid lock
        return SUCCESS;
    }

    int lock_result = flock(pid_lock_fd, LOCK_EX | LOCK_NB);
    if (lock_result < 0) {
        if (errno == EWOULDBLOCK) {
            if (IS_FAIL(pid_lock_handle_multiple_instance())) {
                close(pid_lock_fd);
                pid_lock_fd = 0;
                return FAILURE;
            } // Continue if handled
        } else {
            PR_ERRNO("无法对 PID 文件加锁");
            return FAILURE;
        }
    }

    return SUCCESS;
}

RESULT pid_lock_destroy() {
    if (pid_lock_fd <= 0) {
        return SUCCESS;
    }

    close(pid_lock_fd); // Unlocks the file simultaneously
    if (unlink(get_program_config()->pidfile) < 0) {
        PR_WARN("无法删除 PID 文件");
    }
    return SUCCESS;
}
