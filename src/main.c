#include "strace.h"
#include "colors.h"

void	block_signal(void)
{
	sigset_t blockSet;

	sigemptyset(&blockSet);
	sigaddset(&blockSet, SIGHUP);
	sigaddset(&blockSet, SIGINT);
	sigaddset(&blockSet, SIGQUIT);
	sigaddset(&blockSet, SIGPIPE);
	sigaddset(&blockSet, SIGTERM);
	__ASSERTI(-1, sigprocmask(SIG_BLOCK, &blockSet, NULL), "Sigprocmask");
}

void	release_signal(void)
{
	sigset_t empty_set;

	sigemptyset(&empty_set);
	__ASSERTI(-1, sigprocmask(SIG_SETMASK, &empty_set, NULL), "Sigprocmask");
}

void	signal_handler(int signum)
{

}

void	init_sigaction(int signum)
{
	struct sigaction sa = {
		.sa_sigaction = SIG_DFL,
		.sa_flags = SA_SIGINFO,
	};
	sigemptyset(&sa.sa_mask);

	sigaction(signum, &sa, NULL);
}

void	init_signal(void)
{
	struct sigaction sa = {
		.sa_sigaction = SIG_IGN,
	};

	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);
	sa.sa_sigaction = NULL;
	sa.sa_handler = signal_handler;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

char *get_string(pid_t process, uint64_t reg)
{
	static char		loc_buf[PATH_MAX + 1];
	struct iovec	remote;
	struct iovec	local;

	bzero(loc_buf, sizeof(loc_buf));
	remote.iov_base = (void*)reg;
	remote.iov_len = 68;

	local.iov_base = loc_buf; 
	local.iov_len = PATH_MAX; 

	__ASSERTI(-1, process_vm_readv(process, &local, 1, &remote, 1, 0), "process_vm_readv");
//rajouter espacing function
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
	uint32_t	value;
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
		remote.iov_base = *((uint64_t*)local.iov_base);
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
			printf("%9u %9.1u %s\n",data[i].calls, data[i].errors, syscalls[i].string);
			calls += data[i].calls;
			errors += data[i].errors;
		}
	}
	printf("------ ----------- ----------- --------- --------- ----------------\n");
	printf("100.00    0.000000             %9u %9u total\n", calls, errors);
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
		printf(" {si_signo=%s, si_code=%d, si_pid=%d, si_uid=%d, si_status=%d, si_utime=%d, si_stime=%d} ---\n", \
			signal_macro[info.si_signo], info.si_code, info.si_pid, info.si_uid, info.si_status, info.si_utime, info.si_stime);
		if (signal == SIGSEGV || signal == SIGKILL || signal == SIGABRT) {
			__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, signal), "ptrace ");
			release_signal();
			init_sigaction(child_st);
			waitpid(-1, &child_st, WUNTRACED);
			block_signal();
			printf("+++ killed by %s +++\n", signal_macro[child_st]);
			fflush(stdout);
			close(env.flag.fd);
			kill(getpid(), child_st);
		}
		return (1);
	}
	return (0);
}

int		display_syscall(pid_t process, struct user_regs_struct *regs, int *child_st, struct info data[512])
{
	int				signal = 0;
	siginfo_t		info;

	syscalls[regs->orig_rax].f(process, syscalls[regs->orig_rax], regs);
	data[regs->orig_rax].calls++;
	__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
	release_signal();
	waitpid(-1, child_st, WUNTRACED);
	block_signal();
	if (handle_signal(process, *child_st) == 1)
		return (0);
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

	char *bin = get_binary_path(env.params[0]);
	process = fork();
	if (process == 0) {
		__ASSERTI(-1, execve(bin, env.params, environ), "execve ");
	} else {
		struct user_regs_struct regs;

		if (env.flag.value & F_OUTPUT)
			__ASSERTI(-1, dup2(env.flag.fd, STDOUT_FILENO), "dup2");
	//	__ASSERTI(-1, ptrace(PTRACE_SETOPTIONS, process, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC), "ptrace "); //PTRACE_O_TRACEEXEC to begin on first execve
		__ASSERTI(-1, ptrace(PTRACE_SEIZE, process, NULL, NULL), "ptrace ");
		__ASSERTI(-1, ptrace(PTRACE_INTERRUPT, process, NULL, NULL), "ptrace ");

		init_signal();
		wait(&child_st);
		t_bool status = SYSCALL_OFF;
		while (1)
		{
			__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
			release_signal();
			waitpid(-1, &child_st, WUNTRACED);
			block_signal();
			if (handle_signal(process, child_st) == 1)
				continue ;
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
		display_opt_c(data); //deplacer cette ligne en cas de SEGV / KILL etc...
	}
	close(env.flag.fd);
	return (EXIT_SUCCESS);
}
