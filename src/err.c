#include "strace.h"
#include "colors.h"

char	*error_str[] = {
	[UNKNOWN_TYPE] = RED_TEXT("%s: '%s' is an unknown type\n"),
	[REQUIRED_ARG] = RED_TEXT("%s: '%s' option requires an argument --\n"),
	[INVALID_OPT] = RED_TEXT("%s: invalid option -- '%s'\n"),
	[INVALID_SHORT_OPT] = RED_TEXT("%s: invalid option -- '%c'\n"),
	[UNDEFINED_PARAMETER] = RED_TEXT("%s: Undefined parameters -- '%s'\n"),
	[USAGE_ERR] = RED_TEXT("%s: %s"),
};

static void internal_handle_error(uint32_t line, char *file, t_bool fatal, char *str, ...)
{
	va_list ap;

	va_start(ap, str);
	vfprintf(stderr, str, ap);
	va_end(ap);
	if (DEBUG)
		fprintf(stderr, RED_TEXT("Line : %u, File %s\n"), line, file);
	if (fatal == TRUE)
		exit(EXIT_FAILURE);

}

void	handle_error(uint32_t line, char *file, t_bool fatal, enum error code, ...)
{
	internal_handle_error(line, file, fatal, error_str[code]);
}

int		x_int(int err, int res, char *str, char *file, int line)
{
	if (res == err)
	{
		fprintf(stderr, "%s error (%s, %d): %s\n",\
			str, file, line, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return (res);
}

void	*x_void(void *err, void *res, char *str, char *file, int line)
{
	if (res == err)
	{
		fprintf(stderr, "%s error (%s, %d): %s\n",
				str, file, line, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return (res);
}
