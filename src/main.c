#include "strace.h"
#include "colors.h"

char *get_next_path(char *path)
{
	static int	index = 0;
	char		*ptr = NULL;
	int			previous_index;
	
	if (path[index] == 0)
		return (NULL);	

	if ((ptr = ft_strchr(path + index, ':'))) {
		*ptr = 0;
		previous_index = index;
		index = ptr - path + 1;
		return (path + previous_index);
	} else {
		previous_index = index;
		index = strlen(path);
		return (path + previous_index);
	}
}

char	*search_binary_in_path(char *binary_name)
{
	char	*path;
	char	*concat;
	char	*test;
	struct stat buf;

	if ((path = getenv("PATH")) == NULL) {
		asprintf(&concat, "/bin/%s", binary_name);
		return (concat);
	} else {
		path = strdup(path);
		concat = ft_memalloc(strlen(path) + 1 + strlen(binary_name));
		do
		{
			test = get_next_path(path);
			sprintf(concat, "%s/%s", test, binary_name);
		} while (test != NULL && stat(concat, &buf));
		if (test == NULL) {
			fprintf(stderr, RED_TEXT("%s: Command not found\n"), binary_name); exit(EXIT_FAILURE);
		}
		return (concat);
	}
}

int	main(int argc, char **argv, char **environ)
{
	get_options(argc, argv);
	
	pid_t	process;
	int		child_st = 0;

	process = fork();
	if (process == 0) {
		char *bin;
		if (env.params[0][0] != '/')
			bin = search_binary_in_path(env.params[0]);
		else
			bin = env.params[0];	
		__ASSERTI(-1, execve(bin, env.params, environ), "execve ");
	} else {
		waitpid(process, &child_st, WUNTRACED);
	}
	return (EXIT_SUCCESS);
}
