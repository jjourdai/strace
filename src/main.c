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

/*
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
		value = __ASSERTI(-1, ptrace(PTRACE_PEEKTEXT, process, reg + index, NULL), "ptrace ");
		memcpy(ptr + index, &value, sizeof(value));
		index += 4;
		if (value == 0)
			return (ptr);
		if (index >= size - 4) {
			size *= 2;
			ptr = realloc(ptr, size);
		}
	}
}
*/

char *get_string(pid_t process, uint64_t reg)
{
	uint64_t	size = 4096;
	uint32_t	index = 0;
	uint32_t	value;
	char		ptr[36 + 4] = {0};

	ft_memset(ptr + 36, '.', 3);
	for (;;)
	{
		value = __ASSERTI(-1, ptrace(PTRACE_PEEKTEXT, process, reg + index, NULL), "ptrace ");
		memcpy(ptr + index, &value, sizeof(value));
		index += 4;
		if (value == 0 || index + 4 > 36)
			return (ptr);
	}
}

uint32_t count_elem(pid_t process, uint64_t reg)
{
	uint32_t	value;
	uint32_t	index = 0;

	for (;;)
	{
		value = __ASSERTI(-1, ptrace(PTRACE_PEEKDATA, process, reg + index, NULL), "ptrace ");
		if (value == 0)
			break ;
		index += 8;
	}
	return (index / 8);
}

/*
uint32_t display_env(pid_t process, uint64_t reg)
{
	uint64_t	value;
	uint32_t	index = 0;
	char		*string;

	for (;;)
	{
		value = __ASSERTI(-1, ptrace(PTRACE_PEEKDATA, process, reg + index, NULL), "ptrace ");
		printf("%llx %#llx\n", reg + index , (0xFFFFFFFF00000000 & (reg + index) | (0xffffffff & value)));
		
//		value = __ASSERTI(-1, ptrace(PTRACE_PEEKTEXT, process, (0xFFFFFFFF00000000 & (reg + index) | (0xffffffff & value)), NULL), "ptrace ");
		printf("%s\n", get_string(process, (0xFFFFFFFF00000000 & (reg + index) | (0xffffffff & value))));
		exit(0);
	ft_putendl("JE SUIS LA");

//		printf("%d\n", index / 8);
//		printf("value %llx\n", value);
//		fflush(stdout);
		if (value == 0)
			break ;
		index += 8;
	}
	return (index / 8);
}
*/

extern const struct syscall syscalls[];
extern const char			*err_macro[];

void	general(pid_t process, const struct syscall current, struct user_regs_struct *regs)
{
	uint64_t params[] = {
		[0] = regs->rdi,
		[1] = regs->rsi,
		[2] = regs->rdx,
		[3] = regs->rcx,
		[4] = regs->r8,
		[5] = regs->r9,
	};
	char	line[128] = {0};

	int		index = 0;
	int		i = 0;
	char	*str;

	i += sprintf(line + i, "%s(", current.string);
	while (index < current.params_number)
	{
		if (current.params_type[index] == INT) {
			i += sprintf(line + i, "%d", params[index]);
		} else if (current.params_type[index] == STR) {
			str = get_string(process, params[index]);	
			i += sprintf(line + i, "\"%s\"", str);
		} else if (current.params_type[index] == PTR) {
			if (params[index] == 0) {
				i += sprintf(line + i, "NULL");
			} else {
				i += sprintf(line + i, "%#llx", params[index]);
			}
		} else if (current.params_type[index] == LONG) {
			i += sprintf(line + i, "%llu", params[index]);
		}
		index++;
		if (index < current.params_number)
			i += sprintf(line + i, ", ");
	}	
	sprintf(line + i, ") = ");
	printf("%s", line);
}

void	sys_execve(pid_t process, const struct syscall current, struct user_regs_struct *regs)
{
	char *param1;
	char **param2;
	char **param3;

	printf("%s( = ", current.string);
	param1 = get_string(process, regs->rdi);
	param2 = count_elem(process, regs->rsi);
	param3 = count_elem(process, regs->rdx);
	printf("\"%s\", [\"%u\"], [/* %u vars */]) = ", param1, param2, param3);
}

void	display_opt_c(const struct info data[512])
{
	uint32_t i;
	uint32_t errors = 0;
	uint32_t calls = 0;

	printf("%% time	   seconds  usecs/call     calls    errors syscall\n");
	printf("------ ----------- ----------- --------- --------- ----------------\n");
	for (i = 0; i < 512; i++) {
		if (data[i].calls > 0) {
			printf("  %.2f %11.6f %11u ", data[i].time, data[i].seconds, data[i].usecs_call);
			printf("%9u %9u %s\n",data[i].calls, data[i].errors, syscalls[i].string);
			calls += data[i].calls;
			errors += data[i].errors;
		}
	}
	printf("------ ----------- ----------- --------- --------- ----------------\n");
	printf("100.00    0.000000             %9u %9u total\n", calls, errors);
}

int		display_syscall(pid_t process, struct user_regs_struct *regs, int *child_st, struct info data[512])
{
	syscalls[regs->orig_rax].f(process, syscalls[regs->orig_rax], regs);
	data[regs->orig_rax].calls++;
	__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
	waitpid(process, child_st, WUNTRACED);
	if (WIFEXITED(*child_st))
		return (END);
	__ASSERTI(-1, ptrace(PTRACE_GETREGS, process, NULL, regs), "ptrace ");

	if (syscalls[regs->orig_rax].return_type == INT) {
		if ((int)regs->rax <= syscalls[regs->orig_rax].error) {
			data[regs->orig_rax].errors++;
	 		printf("-1 %s (%s)\n", err_macro[-regs->rax], strerror(-regs->rax));
		} else {
	 		printf("%d\n", regs->rax);
		}
	} else {
		printf("%#llx\n", regs->rax);
	}
	return (0);
}

int	main(int argc, char **argv, char **environ)
{
	get_options(argc, argv);
	pid_t	process;
	int		child_st = 0;
	static struct info data[512];

	bzero(data, sizeof(data));
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

		if (env.flag.value & F_OUTPUT)
			__ASSERTI(-1, dup2(env.flag.fd, STDOUT_FILENO), "dup2");
	//	__ASSERTI(-1, ptrace(PTRACE_SETOPTIONS, process, NULL, PTRACE_O_TRACEEXEC), "ptrace "); //PTRACE_O_TRACEEXEC to begin on first execve
		__ASSERTI(-1, ptrace(PTRACE_SEIZE, process, NULL, NULL), "ptrace ");
		__ASSERTI(-1, ptrace(PTRACE_INTERRUPT, process, NULL, NULL), "ptrace ");

		wait(&child_st);
		t_bool status = SYSCALL_OFF;
		while (1)
		{
			__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
			waitpid(process, &child_st, WUNTRACED);
			__ASSERTI(-1, ptrace(PTRACE_GETREGS, process, NULL, &regs), "ptrace ");
			if (status == SYSCALL_OFF && regs.orig_rax == SYS_execve)
				status = SYSCALL_ENTRY;
			if (status == SYSCALL_ENTRY) {
				if (display_syscall(process, &regs, &child_st, data) == END)
					break ;
			}
		}
		printf("?\n");
		printf("+++ exited with %d +++\n", child_st / 256);
	}
	if (env.flag.value & F_C) {
		display_opt_c(data);
	}
	return (EXIT_SUCCESS);
}
