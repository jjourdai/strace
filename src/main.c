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
		if ((concat = ft_memalloc(strlen(path) + 1 + strlen(binary_name))) == NULL) {
			fprintf(stderr, "Malloc failure\n"); exit(EXIT_FAILURE);
		}
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

char 	*local_binary(char *bin_name)
{
	char	buf[PATH_MAX + 1];
	char	*concat;

	getcwd(buf, PATH_MAX);	
	asprintf(&concat, "%s/%s", buf, bin_name);
	return (concat);
}

char *get_string(pid_t process, uint64_t reg)
{
	uint64_t	size = 4096;
	uint32_t	index = 0;
	uint32_t	value;
	char		*ptr;

	if ((ptr = ft_memalloc(size)) == NULL) {
		fprintf(stderr, "Malloc failure\n"); exit(EXIT_FAILURE);
	}
	for (;;)
	{
		value = __ASSERTI(-1, ptrace(PTRACE_PEEKDATA, process, reg + index, NULL), "ptrace ");
		memcpy(ptr + index, &value, sizeof(value));
		index += 4;
		if (value == 0)
			return (ptr);
		if (index >= size) {
			size *= 2;
			ptr = realloc(ptr, size);
		}
	}
}


extern const char *syscalls[];

int	main(int argc, char **argv, char **environ)
{
	get_options(argc, argv);
	
	pid_t	process;
	int		child_st = 0;

	process = fork();
	if (process == 0) {
		char *bin;
		if (ft_strncmp(env.params[0], "./", 2) == 0) 	/* local path */
			bin = local_binary(env.params[0]);
		else if (env.params[0][0] == '/')				/* obsolut path */
			bin = env.params[0];
		else 											/* relative path */ 
			bin = search_binary_in_path(env.params[0]);
		__ASSERTI(-1, execve(bin, env.params, environ), "execve ");
	} else {
		struct user_regs_struct regs;
		
		__ASSERTI(-1, ptrace(PTRACE_SEIZE, process, NULL, NULL), "ptrace ");
		__ASSERTI(-1, ptrace(PTRACE_INTERRUPT, process, NULL, NULL), "ptrace ");

		wait(&child_st);
		t_bool entry = FALSE;
		while (1)
		{
			__ASSERTI(-1, ptrace(PTRACE_GETREGS, process, NULL, &regs), "ptrace ");
			if (entry == FALSE) {
				printf("%s() = %d\n", syscalls[regs.orig_rax], regs.rax);
				entry = TRUE;
			} else {
				if (regs.orig_rax == SYS_write) {
					printf("%d\n", regs.rdi);
					printf("%d\n", regs.rdx);
					//printf("%s\n", regs.rsi);
				}
				entry = FALSE;
			}
			__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
			waitpid(process, &child_st, WUNTRACED);
			if (WIFEXITED(child_st))
				break ;
		}
	}
	return (EXIT_SUCCESS);
}
