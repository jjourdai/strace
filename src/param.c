/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jjourdai <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/12 12:28:59 by jjourdai          #+#    #+#             */
/*   Updated: 2018/09/19 14:01:29 by jjourdai         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "strace.h"
#include "colors.h"

static t_parameters *store_parameters(char *str, enum options flag)
{
	static t_parameters new_param;

	new_param.str = str;
	new_param.code = flag;
	return (&new_param);
}

static void	open_output_file(char *str, void *ptr)
{
	(void)ptr;
	int fd;

	fd = __ASSERTI(-1, open(str, O_CREAT | O_TRUNC | O_WRONLY, 0644), "open");
	*((int*)ptr) = fd;
	//__ASSERTI(-1, dup2(fd, STDOUT_FILENO), "dup2");
}

static struct params_getter options[] = {
	{"help", 'h', F_HELP, NULL, NULL, DUP_OFF},
	{"ccccc", 'c', F_C, NULL, NULL, DUP_OFF},
	{"output", 'o', F_OUTPUT, open_output_file, &env.flag.fd, DUP_OFF},
};

void	longname_opt(char **argv, uint32_t *flag, int *i)
{
	uint8_t index;
	char	*string;

	string = argv[*i] + 2;
	index = -1;
	while (++index < COUNT_OF(options))
	{
		if (ft_strcmp(options[index].long_name, string) == 0) {
		  if ((*flag & options[index].code) == options[index].code && options[index].dup == DUP_OFF) {
			fprintf(stderr, GREEN_TEXT("nmap: Warning --%s have been previously stored you could have an undefined behaviour\n"), options[index].long_name);
		  }
		  *flag |= options[index].code;
		  if (options[index].f != NULL) {
			if (argv[*i + 1] != NULL) {
			 	return options[index].f(argv[++(*i)], options[index].var);
			} else {
				  __FATAL(REQUIRED_ARG, BINARY_NAME, options[index].long_name);
			}
		  }
		}
	}
  __FATAL(INVALID_OPT, BINARY_NAME, string);
}

void	shortname_opt(char **argv, uint32_t *flag, int *i)
{
	int		j, flag_has_found;
	uint8_t index;
	char	c;

	j = 0;
	while ((c = argv[*i][++j]))
	{
		index = -1;
		flag_has_found = 0;
		while (++index < COUNT_OF(options))
		{
			if (options[index].short_name == c) {
			  flag_has_found = 1;
			  if ((*flag & options[index].code) == options[index].code && options[index].dup == DUP_OFF) {
				fprintf(stderr, GREEN_TEXT("nmap: Warning --%s have been previously stored you could have an undefined behaviour\n"), options[index].long_name);
			  }
			  *flag |= options[index].code;
			  if (options[index].f != NULL) {
				if (argv[*i][j + 1] != '\0') {
					return options[index].f(&argv[*i][++j], options[index].var);
				} else if (argv[*i + 1] != NULL) {
				 	return options[index].f(argv[++(*i)], options[index].var);
				} else {
				  __FATAL(REQUIRED_ARG, BINARY_NAME, options[index].long_name);
				}
			  }
			}
		}
		if (flag_has_found != 1) {
		  __FATAL(INVALID_SHORT_OPT, BINARY_NAME, c);
		}
	}
}

t_list		*get_params(char **argv, int argc, uint32_t *flag)
{
	int 	i;
	t_list	*parameters;

	i = 0;
	parameters = NULL;
	while (++i < argc)
	{
		if (parameters == NULL && ft_strncmp(argv[i], "--", 2) == 0) {
			longname_opt(argv, flag, &i);
		} else if (parameters == NULL && argv[i][0] == '-') {
			shortname_opt(argv, flag, &i);	
		} else {
			list_push_back(&parameters, store_parameters(argv[i], BINARY), sizeof(t_parameters));
		}
	}
	return (parameters);
}

void	format_parameters_for_execve(t_list *params)
{
	char	**bin_params;
	t_list	*tmp;
	size_t	len = list_size(params);
	size_t	i = 0;

	if ((bin_params = ft_memalloc((len + 1) * sizeof(char*))) == NULL) {
		fprintf(stderr, "Malloc failure\n"); exit(EXIT_FAILURE);
	}
	tmp = params;
	if (len == 0) {
		__FATAL(USAGE_ERR, BINARY_NAME, USAGE); 
	}
	while (tmp)
	{
		bin_params[i] = ((t_parameters*)tmp->content)->str;
	//	ft_putendl(bin_params[i]);
		tmp = tmp->next;
		i++;
	}
	env.params = bin_params;
}

void	get_options(int argc, char **argv)
{
	t_list	*parameters;
	ft_bzero(&env, sizeof(env));
	parameters = get_params(argv, argc, (uint32_t*)&env.flag.value);
	if (env.flag.value & F_HELP) {
		fprintf(stderr, GREEN_TEXT(USAGE) GREEN_TEXT(HELPER)); exit(EXIT_FAILURE);
	}
	format_parameters_for_execve(parameters);
	list_remove(&parameters, remove_content);
}
