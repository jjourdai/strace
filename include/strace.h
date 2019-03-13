/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   strace.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jjourdai <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/12/17 18:12:39 by jjourdai          #+#    #+#             */
/*   Updated: 2019/02/01 11:03:40 by jjourdai         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef STRACE_H
# define STRACE_H

# include "libft.h"
# include <errno.h>
# include <stdlib.h>
# include <stdio.h>
# include <stdarg.h>
# include <fcntl.h>
# include <sys/wait.h> 
# include <sys/stat.h> 
# include <sys/ptrace.h> 
# include <sys/user.h> 
# include <linux/elf.h>
# include <sys/uio.h>
# include <bits/uio-ext.h>
# include <sys/time.h>

# define COUNT_OF(ptr) (sizeof(ptr) / sizeof((ptr)[0]))
# define USAGE "[-hoc]\n"

# define HELPER "-h Print this help screen\n"\
				"-o print output in targeted file\n"\
				"-c Doing something\n"
				
# define TRUE 1
# define FALSE 0
# define FATAL TRUE
# define BINARY_NAME "ft_strace"
# define DUP_ON 1
# define DUP_OFF 0

# define DEBUG 0
# define __FATAL(X, ...) handle_error(__LINE__, __FILE__, FATAL, X, __VA_ARGS__)
# define __ASSERTI(ERR_VALUE, RETURN_VALUE, STRING) x_int(ERR_VALUE, RETURN_VALUE, STRING, __FILE__, __LINE__)
# define __ASSERT(ERR_VALUE, RETURN_VALUE, STRING) x_void(ERR_VALUE, RETURN_VALUE, STRING, __FILE__, __LINE__)

# define SYSCALL_ENTRY 1
# define SYSCALL_EXIT 0
# define SYSCALL_OFF -1
# define END 1

# define X86_64 0
# define I386 1

enum	options {
	F_HELP = (1 << 0),
	F_C = (1 << 1),
	F_OUTPUT = (1 << 2),
	BINARY = (1 << 3),
};

enum	error {
	UNKNOWN_TYPE,
	REQUIRED_ARG,
	INVALID_OPT,
	INVALID_SHORT_OPT,
	UNDEFINED_PARAMETER,
	USAGE_ERR,
};

enum	parameters_type {
	INT = 1,
	PTR,
	LONG,
	STR,
	SIG,
};

struct syscall {
	char	*string;
	int		params_number;
	int		params_type[6];
	int		return_type;
	int		error;
	void	(*f)(pid_t process, const struct syscall current);
};

struct strace {
	char	**params;
	sigset_t	blockset;
	sigset_t	emptyset;
	const struct syscall	*syscalls;
	uint32_t		max;
	uint64_t		arg[6];
	uint64_t		sys_nb;
	uint8_t			arch;
	pid_t			proc;
	struct {
		uint8_t		value;
		uint32_t	fd;
	} flag;
};

typedef struct parameters {
	char *str;
	enum options code;
}			t_parameters;

struct params_getter {
	char			*long_name;
	char			short_name;
	enum options	code;
	void	(*f)(char *, void *ptr);	
	void			*var;
	uint8_t			dup;
};

struct info {
	float		time;
	uint64_t	seconds;
	uint64_t	calls;
	uint64_t	errors;
	char		*string;
};

struct strace env;

/* params.c */
t_list	*get_params(char **argv, int argc, uint32_t *flag);
void	get_options(int argc, char **argv);

/* err.c */
void	handle_error(uint32_t line, char *file, t_bool fatal, enum error code, ...);
int		x_int(int err, int res, char *str, char *file, int line);
void	*x_void(void *err, void *res, char *str, char *file, int line);

/* get_path.c */
char	*get_binary_path(char *dest);

void	general(pid_t process, const struct syscall current);
void	sys_execve(pid_t process, const struct syscall current);
void	sys_execve_32(pid_t process, const struct syscall current);

/* signal.c */
void	init_signal(void);
void	init_sigaction(int signum);
void	block_signal(sigset_t *blockSet);
void	release_signal(sigset_t *empty_set);

extern int asprintf(char **__restrict __ptr, const char *__restrict __fmt, ...);

#endif
