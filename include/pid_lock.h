#ifndef MINIEAP_PID_LOCK_H
#define MINIEAP_PID_LOCK_H

RESULT pid_lock_init(const char* pidfile);
RESULT pid_lock_lock();
RESULT pid_lock_save_pid();
RESULT pid_lock_destroy();

#endif