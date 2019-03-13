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

char *get_string(
				pid_t process,
				uint64_t reg)
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

uint32_t count_elem(
				pid_t process,
				uint64_t reg)
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

char	 *display_env(
				pid_t process,
				uint64_t reg)
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

extern const struct syscall syscalls_32[];
extern const uint32_t		syscalls_32_value;
extern const struct syscall syscalls_64[];
extern const uint32_t		syscalls_64_value;

extern const char			*err_macro[];
extern const char			*signal_macro[];

void	general(
				pid_t process,
				const struct syscall current)
{
	char	line[128] = {0};
	int			index = 0;
	uint64_t	i = 0;
	char		*str;
	
	i += sprintf(line + i, "%s(", current.string);
	while (index < current.params_number)
	{
		if (current.params_type[index] == INT) {
			i += sprintf(line + i, "%d", (int)env.arg[index]);
		} else if (current.params_type[index] == STR) {
			str = get_string(process, env.arg[index]);
			i += sprintf(line + i, "\"%s\"", str);
		} else if (current.params_type[index] == PTR) {
			if (env.arg[index] == 0) {
				i += sprintf(line + i, "NULL");
			} else {
				i += sprintf(line + i, "%#llx", (unsigned long long)env.arg[index]);
			}
		} else if (current.params_type[index] == LONG) {
			i += sprintf(line + i, "%llu", (unsigned long long)env.arg[index]);
		} else if (current.params_type[index] == SIG) {
			i += sprintf(line + i, "%s", signal_macro[env.arg[index]]); 
		}
		index++;
		if (index < current.params_number)
			i += sprintf(line + i, ", ");
	}
	fprintf(stderr, "%s", line);
}

void	sys_execve_32(
				pid_t process,
				const struct syscall current)
{
	(void)current;
	fprintf(stderr, "strace: [ Process PID=%d runs in 32 bit mode. ]\n", process);
}

void	sys_execve(
				pid_t process,
				const struct syscall current)
{
	char			*param1;
	char			*param2;
	unsigned int	param3;

	fprintf(stderr, "%s(", current.string);
	param1 = get_string(process, env.arg[0]);
	fprintf(stderr, "\"%s\",", param1);
	param2 = display_env(process, env.arg[1]);
	fprintf(stderr, " [%s],", param2);
	param3 = count_elem(process, env.arg[2]);
	fprintf(stderr, " [/* %u vars */]) = ", param3);
}

void	display_data(struct info data_64[512])
{
	uint32_t i;
	uint32_t errors = 0;
	uint32_t calls = 0;
	float	 time = 0;
	float	 seconds = 0;

	/* Fill informations about performed syscall */
	for (i = 0; i < 512; i++) {
		if (data_64[i].calls > 0) {
			calls += data_64[i].calls;
			errors += data_64[i].errors;
			seconds += (float)data_64[i].seconds / 1000000;
			data_64[i].string = env.syscalls[i].string;
		}
	}
	for (i = 0; i < 512; i++) {
		if (data_64[i].calls > 0) {
			data_64[i].time = ((float)data_64[i].seconds / 1000000) / seconds * 100;
			time += data_64[i].time;
		}
	}
	/* print in order */
	fprintf(stderr, "%% time	   seconds  usecs/call     calls    errors syscall\n");
	fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
	struct info *ptr;
	uint64_t	max = UINT64_MAX;
	while (max > 0) 
	{	
		max = 0;
		for (i = 0; i < 512; i++) {
			if (data_64[i].seconds > max) {
				max = data_64[i].seconds;
				ptr = &data_64[i];
			}
		}
		if (max > 0) {
			fprintf(stderr, " %5.2f %11.6f %11lu ", (float)ptr->time, (float)ptr->seconds / 1000000, ptr->seconds / ptr->calls);
			fprintf(stderr, "%9lu %9.lu %s\n", ptr->calls, ptr->errors, ptr->string);
			ptr->seconds = 0;
		}
	}
	fprintf(stderr, "------ ----------- ----------- --------- --------- ----------------\n");
	fprintf(stderr, "%.2f %11.6f             %9u %9u total\n", time, seconds, calls, errors);

}

void	display_opt_c(
				struct info data_64[512],
				struct info data_32[512])
{
	env.syscalls = syscalls_64;
	display_data(data_64);
	if (env.arch == I386) {
		env.syscalls = syscalls_32;
		fprintf(stderr, "System call usage summary for 32 bit mode:\n");
		display_data(data_32);
	}
}

int		handle_signal(
				pid_t process,
				int child_st)
{
	siginfo_t		info;
	int				signal = 0;

	if (WIFSTOPPED(child_st) && (signal = WSTOPSIG(child_st)) != SIGTRAP) {
		fprintf(stderr, "--- %s", signal_macro[signal]);
		ptrace(PTRACE_GETSIGINFO, process, NULL, &info);
		if (!(env.flag.value & F_C))
			fprintf(stderr, " {si_signo=%s, si_code=%d, si_pid=%d, si_uid=%d, si_status=%d, si_utime=%ld, si_stime=%ld} ---\n", \
				signal_macro[info.si_signo], info.si_code, info.si_pid, info.si_uid, info.si_status, info.si_utime, info.si_stime);
		if (signal != SIGCONT) {
			__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, signal), "ptrace ");
			__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
			waitpid(-1, &child_st, WUNTRACED);
			__ASSERTI(-1, sigprocmask(SIG_BLOCK, &env.blockset, NULL), "Sigprogmask");
			init_sigaction(signal);
		}
		if (WIFSIGNALED(child_st)) {
			__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
			fprintf(stderr, "+++ killed by %s +++\n", signal_macro[signal]);
			fflush(stdout);
			close(env.flag.fd);
			kill(getpid(), signal);
		}
		return (1);
	}
	return (0);
}

uint64_t	handle_timer(
				const struct timeval *now,
				const struct timeval *past)
{
	uint64_t time = ((now->tv_sec) << 20) | (now->tv_usec);
	uint64_t time2 = ((past->tv_sec) << 20) | (past->tv_usec);
	return time - time2;
}

int		store_syscall_data(
				pid_t process,
				struct user_regs_struct *regs,
				int *child_st,
				struct info data[512])
{
	struct timeval bef;
	struct timeval aft;
	const struct syscall *syscalls = env.syscalls;
		
	ft_bzero(&bef, sizeof(bef));
	ft_bzero(&aft, sizeof(aft));
	data[regs->orig_rax].calls++;
		
	__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
	gettimeofday(&bef, NULL);
	__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
	gettimeofday(&aft, NULL);
	waitpid(-1, child_st, WUNTRACED);
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

int		display_syscall(
				pid_t process,
				int *child_st,
				struct user_regs_struct *regs)
{
	struct timeval bef;
	struct timeval aft;

	ft_bzero(&bef, sizeof(bef));
	ft_bzero(&aft, sizeof(aft));
	if (env.sys_nb <= env.max && env.syscalls[env.sys_nb].string != NULL)
		env.syscalls[env.sys_nb].f(process, env.syscalls[env.sys_nb]);
	else
		fprintf(stderr, "Unknown syscall() = ");
	__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
	__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
	waitpid(-1, child_st, WUNTRACED);
	__ASSERTI(-1, sigprocmask(SIG_BLOCK, &env.blockset, NULL), "Sigprogmask");
	fprintf(stderr, ") = ");
	if (handle_signal(process, *child_st) == 1)
		return (0);
	if (WIFEXITED(*child_st))
		return (END);
	__ASSERTI(-1, ptrace(PTRACE_GETREGS, process, NULL, regs), "ptrace ");
	if (env.syscalls[env.sys_nb].return_type == INT) {
		if ((int)regs->rax <= env.syscalls[env.sys_nb].error) {
	 		fprintf(stderr, "-1 %s (%s)\n", err_macro[-regs->rax], strerror(-regs->rax));
		} else {
	 		fprintf(stderr, "%lld\n", regs->rax);
		}
	} else if (regs->rax != 0 && -regs->rax <= ERANGE) {
		fprintf(stderr, "-1 %s (%s)\n", err_macro[-regs->rax], strerror(-regs->rax));
	} else {
		fprintf(stderr, "%#llx\n", regs->rax);
	}
	return (0);
}

void	init_syscall_reg(
				struct user_regs_struct *regs,
				struct iovec *x86_io)
{
	if (x86_io->iov_len == sizeof(struct user_regs_struct)) {
		env.syscalls = (struct syscall*)&syscalls_64;
		env.max = syscalls_64_value;
		env.arg[0] = regs->rdi;
		env.arg[1] = regs->rsi;
		env.arg[2] = regs->rdx;
		env.arg[3] = regs->rcx;
		env.arg[4] = regs->r8;
		env.arg[5] = regs->r9;
		env.arch = X86_64;
	} else {
		env.syscalls = (struct syscall*)&syscalls_32;
		env.max = syscalls_32_value;
		env.arg[0] = regs->rbx;
		env.arg[1] = regs->rcx;
		env.arg[2] = regs->rdx;
		env.arg[3] = regs->rsi;
		env.arg[4] = regs->rdi;
		env.arg[5] = regs->rbp;
		env.arch = I386;
	}
	env.sys_nb = regs->orig_rax;
}

int	main(int argc, char **argv, char **environ)
{
	get_options(argc, argv);
	pid_t	process;
	int		child_st = 0;
	struct info data_64[512];
	struct info data_32[512];

	bzero(data_64, sizeof(data_64));
	bzero(data_32, sizeof(data_32));

	release_signal(&env.emptyset);
	block_signal(&env.blockset);

	char *bin = get_binary_path(env.params[0]);
	process = __ASSERTI(-1, fork(), "Fork ");
	if (process == 0) {
		kill(getpid(), SIGSTOP);
		__ASSERTI(-1, execve(bin, env.params, environ), "execve ");
	} else {
		env.proc = process;
		struct user_regs_struct regs;
		struct iovec x86_io = {
			.iov_base = &regs,
			.iov_len = sizeof(regs),
		};
	
		waitpid(process, &child_st, WUNTRACED);
		__ASSERTI(-1, ptrace(PTRACE_SEIZE, process, NULL, NULL), "ptrace ");
		__ASSERTI(-1, ptrace(PTRACE_INTERRUPT, process, NULL, NULL), "ptrace ");
		if (env.flag.value & F_OUTPUT)
			__ASSERTI(-1, dup2(env.flag.fd, STDERR_FILENO), "dup2");
		kill(process, SIGCONT);
		init_signal();
		__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
		waitpid(process, &child_st, WUNTRACED);
		__ASSERTI(-1, sigprocmask(SIG_BLOCK, &env.blockset, NULL), "Sigprogmask");
		t_bool status = SYSCALL_OFF;
		while (1)
		{
			__ASSERTI(-1, ptrace(PTRACE_SYSCALL, process, NULL, NULL), "ptrace ");
			__ASSERTI(-1, sigprocmask(SIG_SETMASK, &env.emptyset, NULL), "Sigprogmask");
			waitpid(-1, &child_st, WUNTRACED);
			__ASSERTI(-1, sigprocmask(SIG_BLOCK, &env.blockset, NULL), "Sigprogmask");
			if (status == SYSCALL_ENTRY)
				handle_signal(process, child_st);
			__ASSERTI(-1, ptrace(PTRACE_GETREGSET, process, NT_PRSTATUS, &x86_io), "ptrace");
			__ASSERTI(-1, ptrace(PTRACE_GETREGS, process, NULL, &regs), "ptrace ");
			if (status == SYSCALL_OFF && regs.orig_rax == 59) { //syscall_number_execve_64bits
				status = SYSCALL_ENTRY;
			}
			init_syscall_reg(&regs, &x86_io);
			if (status == SYSCALL_ENTRY) {
				if (env.flag.value & F_C) {
					if (store_syscall_data(process, &regs, &child_st, (env.arch == X86_64) ? data_64 : data_32) == END)
						break ;
				}
				else if (display_syscall(process, &child_st, &regs) == END)
					break ;
			}
		}
	}
	if (env.flag.value & F_C) {
		display_opt_c(data_64, data_32); //deplacer cette ligne en cas de SEGV / KILL etc...
	} else {
		fprintf(stderr, "?\n");
		fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(child_st));
	}
	close(env.flag.fd);
	return (EXIT_SUCCESS);
}
