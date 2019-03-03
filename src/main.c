#include "strace.h"
#include "colors.h"

/*
int		is_escape(char c)
{
	if (c <= 13 && c >= 0)
		return (1);
	return (0);
}

char	*espace_special_char(char *ptr)
{
	static const char special_char[] = {
		[0] = '0',
		[7] = 'a',
		[8] = 'b',
		[9] = 't',
		[10] = 'n',
		[11] = 'v',
		[12] = 'f',
		[13] = 'r',
	};
	static		char returned_buf[PATH_MAX + 1];
	int			j = 0;

	for (int i = 0; i < 34; i++)
	{
		if (is_escape(ptr[i]) && special_char[(int)ptr[i]]) {
			returned_buf[j++] = '\\';
			returned_buf[j++] = special_char[(int)ptr[i]];
			continue ;
		}
		returned_buf[j++] = ptr[i];
	}
	return (returned_buf);
}
*/

char *get_string(pid_t process, uint64_t reg)
{
	static char		loc_buf[PATH_MAX + 1];
	struct iovec	remote;
	struct iovec	local;

	bzero(loc_buf, sizeof(loc_buf));
	remote.iov_base = (void*)reg;
	remote.iov_len = 34;

	local.iov_base = loc_buf; 
	local.iov_len = PATH_MAX; 

	__ASSERTI(-1, process_vm_readv(process, &local, 1, &remote, 1, 0), "process_vm_readv");
	return (loc_buf);
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

char	 *display_env(pid_t process, uint64_t reg)
{
	uint32_t	index = 0;
	char		*ptr;
	static char		result[PATH_MAX + 1] = {0};
	size_t			size = 0;


	struct		iovec remote;
	struct		iovec local;
	char		loc_buf[PATH_MAX + 1];


	remote.iov_len = 8;
	local.iov_base = loc_buf;
	local.iov_len = PATH_MAX;
	for (;;)
	{
		remote.iov_base = (void*)(reg + index);
		__ASSERTI(-1, process_vm_readv(process, &local, 1, &remote, 1, 0), "process_vm_readv");
		remote.iov_base = (void*)*((uint64_t*)local.iov_base);
		if (*((uint64_t*)local.iov_base) == 0)
			break ;
		index += 8;
		ptr = get_string(process, *((uint64_t*)local.iov_base));
		if (size + strlen(ptr) > PATH_MAX)
			break ;
		if (size == 0)
			size += sprintf(result + size, "\"%s\"", ptr);
		else
			size += sprintf(result + size, ", \"%s\"", ptr);
	}
	return (result);
}

extern const struct syscall syscalls[];
extern const char			*err_macro[];
extern const char			*signal_macro[];

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
	int			index = 0;
	uint64_t	i = 0;
	char		*str;

	i += sprintf(line + i, "%s(", current.string);
	while (index < current.params_number)
	{
		if (current.params_type[index] == INT) {
			i += sprintf(line + i, "%d", (int)params[index]);
		} else if (current.params_type[index] == STR) {
			str = get_string(process, params[index]);	
			i += sprintf(line + i, "\"%s\"", str);
		} else if (current.params_type[index] == PTR) {
			if (params[index] == 0) {
				i += sprintf(line + i, "NULL");
			} else {
				i += sprintf(line + i, "%#llx", (unsigned long long)params[index]);
			}
		} else if (current.params_type[index] == LONG) {
			i += sprintf(line + i, "%llu", (unsigned long long)params[index]);
		} else if (current.params_type[index] == SIG) {
			i += sprintf(line + i, "%s", signal_macro[params[index]]); 
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
	char			*param1;
	char			*param2;
	unsigned int	param3;

	printf("%s(", current.string);
	param1 = get_string(process, regs->rdi);
	printf("\"%s\",", param1);
	param2 = display_env(process, regs->rsi);
	printf(" [%s],", param2);
	param3 = count_elem(process, regs->rdx);
	printf(" [/* %u vars */]) = ", param3);
}

void	display_opt_c(struct info data[512])
{
	uint32_t i;
	uint32_t errors = 0;
	uint32_t calls = 0;
	float	 seconds = 0;

	fprintf(stderr, "%% time	   seconds  usecs/call     calls    errors syscall\n");
	fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
	for (i = 0; i < 512; i++) {
		if (data[i].calls > 0) {
			calls += data[i].calls;
			errors += data[i].errors;
			seconds += (float)data[i].seconds / 1000000;
		}
	}
	for (i = 0; i < 512; i++) {
		if (data[i].calls > 0) {
			data[i].time = ((float)data[i].seconds / 1000000) / seconds * 100;
		//	fprintf(stderr, " %5.2f %11.6f %11lu ", (float)data[i].time, (float)data[i].seconds / 1000000, data[i].seconds / data[i].calls);
		//	fprintf(stderr, "%9lu %9.lu %s\n", data[i].calls, data[i].errors, syscalls[i].string);
		}
	}
	fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
	fprintf(stderr, "100.00 %11.6f             %9u %9u total\n", seconds, calls, errors);
}

int		handle_signal(pid_t process, int child_st)
{
	siginfo_t		info;
	int				signal = 0;
	
	if (WIFSIGNALED(child_st) && (signal = WTERMSIG(child_st)) != SIGTRAP) {
		printf("<unfinished ...>\n+++ killed by %s +++\n", signal_macro[signal]);
		fflush(stdout);
		close(env.flag.fd);
		kill(getpid(), signal);
	}
	if (WIFSTOPPED(child_st) && (signal = WSTOPSIG(child_st)) != SIGTRAP) {
		printf("--- %s", signal_macro[signal]);
		ptrace(PTRACE_GETSIGINFO, process, NULL, &info);
		if (!(env.flag.value & F_C))
			printf(" {si_signo=%s, si_code=%d, si_pid=%d, si_uid=%d, si_status=%d, si_utime=%ld, si_stime=%ld} ---\n", \
				signal_macro[info.si_signo], info.si_code, info.si_pid, info.si_uid, info.si_status, info.si_utime, info.si_stime);
		if (signal != SIGCONT) {
			__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, signal), "ptrace ");
			__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
			waitpid(-1, &child_st, WUNTRACED);
			__ASSERTI(-1, sigprocmask(SIG_BLOCK, &env.blockset, NULL), "Sigprogmask");
		}
		if (signal == SIGSEGV || signal == SIGKILL || signal == SIGABRT) {
			init_sigaction(child_st);
			printf("+++ killed by %s +++\n", signal_macro[signal]);
			fflush(stdout);
			close(env.flag.fd);
			kill(getpid(), signal);
		}
		return (1);
	}
	return (0);
}

uint64_t	handle_timer(const struct timeval *now, const struct timeval *past)
{
	uint64_t time = ((now->tv_sec) << 20) | (now->tv_usec);
	uint64_t time2 = ((past->tv_sec) << 20) | (past->tv_usec);
	return time - time2;
}

int		store_syscall_data(pid_t process, struct user_regs_struct *regs, int *child_st, struct info data[512])
{
	struct timeval bef;
	struct timeval aft;
		
	ft_bzero(&bef, sizeof(bef));
	ft_bzero(&aft, sizeof(aft));
	data[regs->orig_rax].calls++;
		
	__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
	__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
	gettimeofday(&bef, NULL);
	waitpid(-1, child_st, WUNTRACED);
	gettimeofday(&aft, NULL);
	data[regs->orig_rax].seconds += handle_timer(&aft, &bef);
	__ASSERTI(-1, sigprocmask(SIG_BLOCK, &env.blockset, NULL), "Sigprogmask");
	if (handle_signal(process, *child_st) == 1)
		return (0);
	if (WIFEXITED(*child_st))
		return (END);
	__ASSERTI(-1, ptrace(PTRACE_GETREGS, process, NULL, regs), "ptrace ");
	if (syscalls[regs->orig_rax].return_type == INT) {
		if ((int)regs->rax <= syscalls[regs->orig_rax].error) {
			data[regs->orig_rax].errors++;
		}
	} else if (regs->rax != 0 && -regs->rax <= ERANGE) {
		data[regs->orig_rax].errors++;
	}
	return (0);
}

int		display_syscall(pid_t process, struct user_regs_struct *regs, int *child_st)
{
	struct timeval bef;
	struct timeval aft;
		
	ft_bzero(&bef, sizeof(bef));
	ft_bzero(&aft, sizeof(aft));
	syscalls[regs->orig_rax].f(process, syscalls[regs->orig_rax], regs);
		
	__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
	gettimeofday(&bef, NULL);
	__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
	gettimeofday(&aft, NULL);
	waitpid(-1, child_st, WUNTRACED);
	__ASSERTI(-1, sigprocmask(SIG_BLOCK, &env.blockset, NULL), "Sigprogmask");
	if (handle_signal(process, *child_st) == 1)
		return (0);
	if (WIFEXITED(*child_st))
		return (END);
	__ASSERTI(-1, ptrace(PTRACE_GETREGS, process, NULL, regs), "ptrace ");
	if (syscalls[regs->orig_rax].return_type == INT) {
		if ((int)regs->rax <= syscalls[regs->orig_rax].error) {
	 		printf("-1 %s (%s)\n", err_macro[-regs->rax], strerror(-regs->rax));
		} else {
	 		printf("%lld\n", regs->rax);
		}
	} else if (regs->rax != 0 && -regs->rax <= ERANGE) {
		printf("-1 %s (%s)\n", err_macro[-regs->rax], strerror(-regs->rax));
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
	release_signal(&env.emptyset);
	block_signal(&env.blockset);

	char *bin = get_binary_path(env.params[0]);
	process = __ASSERTI(-1, fork(), "Fork ");
	if (process == 0) {
		kill(getpid(), SIGSTOP);
		__ASSERTI(-1, execve(bin, env.params, environ), "execve ");
	} else {
		struct user_regs_struct regs;

		waitpid(process, &child_st, WUNTRACED);
		__ASSERTI(-1, ptrace(PTRACE_SEIZE, process, NULL, NULL), "ptrace ");
		__ASSERTI(-1, ptrace(PTRACE_INTERRUPT, process, NULL, NULL), "ptrace ");
		if (env.flag.value & F_OUTPUT)
			__ASSERTI(-1, dup2(env.flag.fd, STDOUT_FILENO), "dup2");
		kill(process, SIGCONT);
		waitpid(process, &child_st, WUNTRACED);
		init_signal();

		t_bool status = SYSCALL_OFF;
		while (1)
		{
			__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
			__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
			waitpid(-1, &child_st, WUNTRACED);
			__ASSERTI(-1, sigprocmask(SIG_BLOCK, &env.blockset, NULL), "Sigprogmask");
			if (status == SYSCALL_ENTRY)
				handle_signal(process, child_st);
			__ASSERTI(-1, ptrace(PTRACE_GETREGS, process, NULL, &regs), "ptrace ");
			if (status == SYSCALL_OFF && regs.orig_rax == SYS_execve) {
				status = SYSCALL_ENTRY;
			}
			if (status == SYSCALL_ENTRY) {
				if (env.flag.value & F_C) {
					if (store_syscall_data(process, &regs, &child_st, data) == END)
						break ;
				}
				else if (display_syscall(process, &regs, &child_st) == END)
					break ;
			}
		}
	}
	if (env.flag.value & F_C) {
		display_opt_c(data); //deplacer cette ligne en cas de SEGV / KILL etc...
	} else {
		printf("?\n");
		printf("+++ exited with %d +++\n", WEXITSTATUS(child_st));
	}
	close(env.flag.fd);
	return (EXIT_SUCCESS);
}
