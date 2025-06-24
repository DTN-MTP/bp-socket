#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>
#include <stdarg.h>

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_DEBUG
#endif

#define log_debug(fmt, ...)                         \
	do                                              \
	{                                               \
		if (LOG_LEVEL <= LOG_LEVEL_DEBUG)           \
			log_print("DEBUG", fmt, ##__VA_ARGS__); \
	} while (0)
#define log_info(fmt, ...)                         \
	do                                             \
	{                                              \
		if (LOG_LEVEL <= LOG_LEVEL_INFO)           \
			log_print("INFO", fmt, ##__VA_ARGS__); \
	} while (0)
#define log_warn(fmt, ...)                         \
	do                                             \
	{                                              \
		if (LOG_LEVEL <= LOG_LEVEL_WARN)           \
			log_print("WARN", fmt, ##__VA_ARGS__); \
	} while (0)
#define log_error(fmt, ...)                         \
	do                                              \
	{                                               \
		if (LOG_LEVEL <= LOG_LEVEL_ERROR)           \
			log_print("ERROR", fmt, ##__VA_ARGS__); \
	} while (0)

static inline void log_print(const char *level, const char *fmt, ...)
{
	time_t t = time(NULL);
	struct tm *lt = localtime(&t);
	char timebuf[20];
	strftime(timebuf, sizeof(timebuf), "%H:%M:%S", lt);

	fprintf(stderr, "[%s] %s: ", timebuf, level);

	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");
}

#endif