#include "strace.h"

const struct syscall syscalls[] = {
		[SYS_read]	=	{"read", 3, {INT, STR, LONG, 0, 0, 0}, INT, -1, general},
		[SYS_write]	=	{"write", 3, {INT, STR, LONG, 0, 0, 0}, INT, -1, general},
		[SYS_open]	=	{"open", 3, {STR, INT, INT, 0, 0, 0}, INT, -1, general},
		[SYS_close]	=	{"close", 1, {INT, 0, 0, 0, 0, 0}, INT, -1, general},
		[SYS_stat]	=	{"stat", 2, {STR, PTR, 0, 0, 0, 0}, INT, -1, general},
		[SYS_fstat]	=	{"fstat", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[SYS_lstat]	=	{"lstat", 2, {STR, PTR, 0, 0, 0, 0}, INT, -1, general},
		[SYS_poll]	=	{"poll", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_lseek]	=	{"lseek", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mmap]	=	{"mmap", 6, {PTR, LONG, INT, INT, INT, LONG}, PTR, 0, general},
		[SYS_mprotect]	=	{"mprotect", 3, {PTR, LONG, INT, 0, 0, 0}, INT, -1, general},
		[SYS_munmap]	=	{"munmap", 2, {PTR, LONG, 0, 0, 0}, 0, -1, general},
		[SYS_brk]	=	{"brk", 1, {PTR, 0, 0, 0, 0}, PTR, 0, general},
		[SYS_rt_sigaction]	=	{"rt_sigaction", 3, {SIG, PTR, PTR, 0, 0, 0}, INT, -1, general},
		[SYS_rt_sigprocmask]	=	{"rt_sigprocmask", 3, {INT, PTR, PTR, 0, 0, 0}, INT, -1, general},
		[SYS_rt_sigreturn]	=	{"rt_sigreturn", 1, {LONG, 0, 0, 0, 0, 0}, INT, 0, general},
		[SYS_ioctl]	=	{"ioctl", 2, {INT, LONG, 0, 0, 0, 0}, INT, -1, general},
		[SYS_pread64]	=	{"pread64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pwrite64]	=	{"pwrite64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_readv]	=	{"readv", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_writev]	=	{"writev", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_access]	=	{"access", 2, {STR, INT, 0, 0, 0}, INT, -1, general},
		[SYS_pipe]	=	{"pipe", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_select]	=	{"select", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_yield]	=	{"sched_yield", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mremap]	=	{"mremap", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_msync]	=	{"msync", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mincore]	=	{"mincore", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_madvise]	=	{"madvise", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_shmget]	=	{"shmget", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_shmat]	=	{"shmat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_shmctl]	=	{"shmctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_dup]	=	{"dup", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_dup2]	=	{"dup2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pause]	=	{"pause", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_nanosleep]	=	{"nanosleep", 2, {PTR, PTR, 0, 0, 0, 0}, INT, -1, general},
		[SYS_getitimer]	=	{"getitimer", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_alarm]	=	{"alarm", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setitimer]	=	{"setitimer", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getpid]	=	{"getpid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sendfile]	=	{"sendfile64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_socket]	=	{"socket", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_connect]	=	{"connect", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_accept]	=	{"accept", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sendto]	=	{"sendto", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_recvfrom]	=	{"recvfrom", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sendmsg]	=	{"sendmsg", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_recvmsg]	=	{"recvmsg", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_shutdown]	=	{"shutdown", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_bind]	=	{"bind", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_listen]	=	{"listen", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getsockname]	=	{"getsockname", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getpeername]	=	{"getpeername", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_socketpair]	=	{"socketpair", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setsockopt]	=	{"setsockopt", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getsockopt]	=	{"getsockopt", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_clone]	=	{"clone", 4, {INT, PTR, INT, PTR, 0, 0}, INT, -1, general},
		[SYS_fork]	=	{"fork", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_vfork]	=	{"vfork", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_execve]	=	{"execve", 0, {0, 0, 0, 0, 0, 0}, INT, -1, sys_execve},
		[SYS_exit]	=	{"exit", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_wait4]	=	{"wait4", 4, {INT, PTR, INT, PTR, 0, 0}, LONG, 0, general},
		[SYS_kill]	=	{"kill", 2, {INT, SIG, 0, 0, 0, 0}, INT, 0, general},
		[SYS_uname]	=	{"newuname", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_semget]	=	{"semget", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_semop]	=	{"semop", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_semctl]	=	{"semctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_shmdt]	=	{"shmdt", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_msgget]	=	{"msgget", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_msgsnd]	=	{"msgsnd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_msgrcv]	=	{"msgrcv", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_msgctl]	=	{"msgctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fcntl]	=	{"fcntl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_flock]	=	{"flock", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fsync]	=	{"fsync", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fdatasync]	=	{"fdatasync", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_truncate]	=	{"truncate", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_ftruncate]	=	{"ftruncate", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getdents]	=	{"getdents", 3, {LONG, PTR, LONG, 0, 0, 0}, INT, -1, general},
		[SYS_getcwd]	=	{"getcwd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_chdir]	=	{"chdir", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fchdir]	=	{"fchdir", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_rename]	=	{"rename", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mkdir]	=	{"mkdir", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_rmdir]	=	{"rmdir", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_creat]	=	{"creat", 2, {STR, INT, 0, 0, 0, 0}, 0, -1, general},
		[SYS_link]	=	{"link", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_unlink]	=	{"unlink", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_symlink]	=	{"symlink", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_readlink]	=	{"readlink", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_chmod]	=	{"chmod", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fchmod]	=	{"fchmod", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_chown]	=	{"chown", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fchown]	=	{"fchown", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_lchown]	=	{"lchown", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_umask]	=	{"umask", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_gettimeofday]	=	{"gettimeofday", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getrlimit]	=	{"getrlimit", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[SYS_getrusage]	=	{"getrusage", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sysinfo]	=	{"sysinfo", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_times]	=	{"times", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_ptrace]	=	{"ptrace", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getuid]	=	{"getuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_syslog]	=	{"syslog", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getgid]	=	{"getgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setuid]	=	{"setuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setgid]	=	{"setgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_geteuid]	=	{"geteuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getegid]	=	{"getegid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setpgid]	=	{"setpgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getppid]	=	{"getppid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getpgrp]	=	{"getpgrp", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setsid]	=	{"setsid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setreuid]	=	{"setreuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setregid]	=	{"setregid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getgroups]	=	{"getgroups", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setgroups]	=	{"setgroups", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setresuid]	=	{"setresuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getresuid]	=	{"getresuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setresgid]	=	{"setresgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getresgid]	=	{"getresgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getpgid]	=	{"getpgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setfsuid]	=	{"setfsuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setfsgid]	=	{"setfsgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getsid]	=	{"getsid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_capget]	=	{"capget", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_capset]	=	{"capset", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_rt_sigpending]	=	{"rt_sigpending", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_rt_sigtimedwait]	=	{"rt_sigtimedwait", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_rt_sigqueueinfo]	=	{"rt_sigqueueinfo", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_rt_sigsuspend]	=	{"rt_sigsuspend", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sigaltstack]	=	{"sigaltstack", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_utime]	=	{"utime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mknod]	=	{"mknod", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_personality]	=	{"personality", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_ustat]	=	{"ustat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_statfs]	=	{"statfs", 2, {STR, PTR, 0, 0, 0, 0}, INT, -1, general},
		[SYS_fstatfs]	=	{"fstatfs", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[SYS_sysfs]	=	{"sysfs", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getpriority]	=	{"getpriority", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setpriority]	=	{"setpriority", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_setparam]	=	{"sched_setparam", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_getparam]	=	{"sched_getparam", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_setscheduler]=	{"sched_setscheduler", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_getscheduler]=	{"sched_getscheduler", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_get_priority_max]=	{"sched_get_priority_max", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_get_priority_min]=	{"sched_get_priority_min", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_rr_get_interval]=	{"sched_rr_get_interval", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mlock]	=	{"mlock", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_munlock]	=	{"munlock", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mlockall]	=	{"mlockall", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_munlockall]	=	{"munlockall", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_vhangup]	=	{"vhangup", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_modify_ldt]	=	{"modify_ldt", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pivot_root]	=	{"pivot_root", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS__sysctl]	=	{"sysctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_prctl]	=	{"prctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_arch_prctl]	=	{"arch_prctl", 2, {INT, LONG, 0, 0, 0, 0}, INT, -1, general},
		[SYS_adjtimex]	=	{"adjtimex", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setrlimit]	=	{"setrlimit", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[SYS_chroot]	=	{"chroot", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sync]	=	{"sync", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_acct]	=	{"acct", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_settimeofday]	=	{"settimeofday", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mount]	=	{"mount", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_umount2]	=	{"umount", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_swapon]	=	{"swapon", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_swapoff]	=	{"swapoff", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_reboot]	=	{"reboot", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sethostname]	=	{"sethostname", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setdomainname]	=	{"setdomainname", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_iopl]	=	{"iopl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_ioperm]	=	{"ioperm", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_init_module]	=	{"init_module", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_delete_module]	=	{"delete_module", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_quotactl]	=	{"quotactl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_gettid]	=	{"gettid", 0, {0, 0, 0, 0, 0, 0}, INT, 0, general},
		[SYS_readahead]	=	{"readahead", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setxattr]	=	{"setxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_lsetxattr]	=	{"lsetxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fsetxattr]	=	{"fsetxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getxattr]	=	{"getxattr", 4, {STR, STR, PTR, LONG, 0, 0}, INT, -1, general},
		[SYS_lgetxattr]	=	{"lgetxattr", 4, {STR, STR, PTR, LONG, 0, 0}, INT, -1, general},
		[SYS_fgetxattr]	=	{"fgetxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_listxattr]	=	{"listxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_llistxattr]	=	{"llistxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_flistxattr]	=	{"flistxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_removexattr]	=	{"removexattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_lremovexattr]	=	{"lremovexattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fremovexattr]	=	{"fremovexattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_tkill]	=	{"tkill", 2, {INT, SIG, 0, 0, 0, 0}, INT, -1, general},
		[SYS_time]	=	{"time", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_futex]	=	{"futex", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_setaffinity]=	{"sched_setaffinity", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_getaffinity]=	{"sched_getaffinity", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_io_setup]	=	{"io_setup", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_io_destroy]	=	{"io_destroy", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_io_getevents]	=	{"io_getevents", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_io_submit]	=	{"io_submit", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_io_cancel]	=	{"io_cancel", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_lookup_dcookie]	=	{"lookup_dcookie", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_epoll_create]	=	{"epoll_create", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_remap_file_pages]=	{"remap_file_pages", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getdents64]	=	{"getdents64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_set_tid_address]	=	{"set_tid_address", 1, {PTR, 0, 0, 0, 0, 0}, LONG, 0, general},
		[SYS_restart_syscall]	=	{"restart_syscall", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_semtimedop]	=	{"semtimedop", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fadvise64]	=	{"fadvise64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_timer_create]	=	{"timer_create", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_timer_settime]	=	{"timer_settime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_timer_gettime]	=	{"timer_gettime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_timer_getoverrun]=	{"timer_getoverrun", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_timer_delete]	=	{"timer_delete", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_clock_settime]	=	{"clock_settime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_clock_gettime]	=	{"clock_gettime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_clock_getres]	=	{"clock_getres", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_clock_nanosleep]	=	{"clock_nanosleep", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_exit_group]	=	{"exit_group", 1, {INT, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_epoll_wait]	=	{"epoll_wait", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_epoll_ctl]	=	{"epoll_ctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_tgkill]	=	{"tgkill", 3, {INT, INT, SIG, 0, 0, 0}, INT, -1, general},
		[SYS_utimes]	=	{"utimes", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mbind]	=	{"mbind", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_set_mempolicy]	=	{"set_mempolicy", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_get_mempolicy]	=	{"get_mempolicy", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mq_open]	=	{"mq_open", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mq_unlink]	=	{"mq_unlink", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mq_timedsend]	=	{"mq_timedsend", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mq_timedreceive]	=	{"mq_timedreceive", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mq_notify]	=	{"mq_notify", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mq_getsetattr]	=	{"mq_getsetattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_kexec_load]	=	{"kexec_load", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_waitid]	=	{"waitid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_add_key]	=	{"add_key", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_request_key]	=	{"request_key", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_keyctl]	=	{"keyctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_ioprio_set]	=	{"ioprio_set", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_ioprio_get]	=	{"ioprio_get", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_inotify_init]	=	{"inotify_init", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_inotify_add_watch] =	{"inotify_add_watch", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_inotify_rm_watch]=	{"inotify_rm_watch", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_migrate_pages]	=	{"migrate_pages", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_openat]	=	{"openat", 4, {INT, STR, INT, INT, 0, 0}, INT, -1, general},
		[SYS_mkdirat]	=	{"mkdirat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mknodat]	=	{"mknodat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fchownat]	=	{"fchownat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_futimesat]	=	{"futimesat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_newfstatat]	=	{"newfstatat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_unlinkat]	=	{"unlinkat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_renameat]	=	{"renameat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_linkat]	=	{"linkat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_symlinkat]	=	{"symlinkat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_readlinkat]	=	{"readlinkat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fchmodat]	=	{"fchmodat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_faccessat]	=	{"faccessat", 4, {INT, STR, INT, INT, 0}, INT, -1, general},
		[SYS_pselect6]	=	{"pselect6", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_ppoll]	=	{"ppoll", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_unshare]	=	{"unshare", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_set_robust_list]	=	{"set_robust_list", 2, {INT, PTR, LONG, 0, 0, 0}, LONG, -1, general},
		[SYS_get_robust_list]	=	{"get_robust_list", 3, {PTR, LONG, 0, 0, 0, 0}, LONG, -1, general},
		[SYS_splice]	=	{"splice", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_tee]	=	{"tee", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sync_file_range]	=	{"sync_file_range", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_vmsplice]	=	{"vmsplice", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_move_pages]	=	{"move_pages", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_utimensat]	=	{"utimensat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_epoll_pwait]	=	{"epoll_pwait", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_signalfd]	=	{"signalfd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_timerfd_create]	=	{"timerfd_create", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_eventfd]	=	{"eventfd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fallocate]	=	{"fallocate", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_timerfd_settime]	=	{"timerfd_settime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_timerfd_gettime]	=	{"timerfd_gettime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_accept4]	=	{"accept4", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_signalfd4]	=	{"signal", 2, {SIG, PTR, 0, 0, 0, 0}, PTR, -1, general},
		[SYS_eventfd2]	=	{"eventfd2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_epoll_create1]	=	{"epoll_create1", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_dup3]	=	{"dup3", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pipe2]	=	{"pipe2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_inotify_init1]	=	{"inotify_init1", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_preadv]	=	{"preadv", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pwritev]	=	{"pwritev", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_rt_tgsigqueueinfo]=	{"rt_tgsigqueueinfo", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_perf_event_open]	=	{"perf_event_open", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_recvmmsg]	=	{"recvmmsg", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fanotify_init]	=	{"fanotify_init", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_fanotify_mark]	=	{"fanotify_mark", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_prlimit64]	=	{"prlimit64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_name_to_handle_at]=	{"name_to_handle_at", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_open_by_handle_at]=	{"open_by_handle_at", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_clock_adjtime]	=	{"clock_adjtime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_syncfs]	=	{"syncfs", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sendmmsg]	=	{"sendmmsg", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_setns]	=	{"setns", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getcpu]	=	{"getcpu", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_process_vm_readv]=	{"process_vm_readv", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_process_vm_writev]=	{"process_vm_writev", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_kcmp]	=	{"kcmp", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_finit_module]	=	{"finit_module", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_setattr]	=	{"sched_setattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_sched_getattr]	=	{"sched_getattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_renameat2]	=	{"renameat2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
/*
		[SYS_seccomp]	=	{"seccomp", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_getrandom]	=	{"getrandom", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_memfd_create]	=	{"memfd_create", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_kexec_file_load]	=	{"kexec_file_load", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_bpf]	=	{"bpf", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_execveat]	=	{"execveat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_userfaultfd]	=	{"userfaultfd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_membarrier]	=	{"membarrier", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_mlock2]	=	{"mlock2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_copy_file_range]	=	{"copy_file_range", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_preadv2]	=	{"preadv2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pwritev2]	=	{"pwritev2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pkey_mprotect]	=	{"pkey_mprotect", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pkey_alloc]	=	{"pkey_alloc", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_pkey_free]	=	{"pkey_free", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_statx]	=	{"statx", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_io_pgetevents]	=	{"io_pgetevents", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[SYS_rseq]	=	{"rseq", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
*/
};
