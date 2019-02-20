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
# include <sys/syscall.h> 
# include <sys/reg.h> 
# include <linux/elf.h>

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

# define DEBUG 1
# define __FATAL(X, ...) handle_error(__LINE__, __FILE__, FATAL, X, __VA_ARGS__)
# define __ASSERTI(ERR_VALUE, RETURN_VALUE, STRING) x_int(ERR_VALUE, RETURN_VALUE, STRING, __FILE__, __LINE__)
# define __ASSERT(ERR_VALUE, RETURN_VALUE, STRING) x_void(ERR_VALUE, RETURN_VALUE, STRING, __FILE__, __LINE__)

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

struct strace {
	char	**params;
	struct {
		uint8_t		value;
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

struct strace env;

/* params.c */
t_list	*get_params(char **argv, int argc, uint32_t *flag);
void	get_options(int argc, char **argv);

/* err.c */
void	handle_error(uint32_t line, char *file, t_bool fatal, enum error code, ...);
int		x_int(int err, int res, char *str, char *file, int line);
void	*x_void(void *err, void *res, char *str, char *file, int line);


#endif
