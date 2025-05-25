#ifndef LOG_H
#define LOG_H

#include <time.h>
#include <sys/socket.h>

typedef enum log_level
{
	LOG_DEBUG,
	LOG_INFO,
	LOG_WARNING,
	LOG_ERROR,
} log_level_t;

#ifndef NO_LOG
int log_init(const char *log_filename, log_level_t level);
void log_printf(log_level_t level, const char *format, ...);
void log_printf_addr(struct sockaddr *addr);
void log_close(void);
#else
#define noop
#define log_init(X, Y) ((int)0)
#define log_printf(...) noop
#define log_printf_addr(...) noop
#define log_close() noop
#endif

int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);

#endif
