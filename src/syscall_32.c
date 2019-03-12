#include <asm/unistd_32.h>
#include "strace.h"

const struct syscall syscalls_32[] = {
		[__NR_read]	=	{"read", 3, {INT, STR, LONG, 0, 0, 0}, INT, -1, general},
		[__NR_write]	=	{"write", 3, {INT, STR, LONG, 0, 0, 0}, INT, -1, general},
		[__NR_open]	=	{"open", 3, {STR, INT, INT, 0, 0, 0}, INT, -1, general},
		[__NR_close]	=	{"close", 1, {INT, 0, 0, 0, 0, 0}, INT, -1, general},
		[__NR_stat]	=	{"stat", 2, {STR, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_fstat]	=	{"fstat", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_fstat64]	=	{"fstat", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_lstat]	=	{"lstat", 2, {STR, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_poll]	=	{"poll", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_lseek]	=	{"lseek", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mmap2]	=	{"mmap2", 6, {PTR, LONG, INT, INT, INT, LONG}, PTR, 0, general},
		[__NR_mprotect]	=	{"mprotect", 3, {PTR, LONG, INT, 0, 0, 0}, INT, -1, general},
		[__NR_munmap]	=	{"munmap", 2, {PTR, LONG, 0, 0, 0}, 0, -1, general},
		[__NR_brk]	=	{"brk", 1, {PTR, 0, 0, 0, 0}, PTR, 0, general},
		[__NR_rt_sigaction]	=	{"rt_sigaction", 3, {SIG, PTR, PTR, 0, 0, 0}, INT, -1, general},
		[__NR_rt_sigprocmask]	=	{"rt_sigprocmask", 3, {INT, PTR, PTR, 0, 0, 0}, INT, -1, general},
		[__NR_rt_sigreturn]	=	{"rt_sigreturn", 1, {LONG, 0, 0, 0, 0, 0}, INT, 0, general},
		[__NR_ioctl]	=	{"ioctl", 2, {INT, LONG, 0, 0, 0, 0}, INT, -1, general},
		[__NR_pread64]	=	{"pread64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pwrite64]	=	{"pwrite64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_readv]	=	{"readv", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_writev]	=	{"writev", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_access]	=	{"access", 2, {STR, INT, 0, 0, 0}, INT, -1, general},
		[__NR_pipe]	=	{"pipe", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_select]	=	{"select", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_yield]	=	{"sched_yield", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mremap]	=	{"mremap", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_msync]	=	{"msync", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mincore]	=	{"mincore", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_madvise]	=	{"madvise", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
/*
		[__NR_shmget]	=	{"shmget", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_shmat]	=	{"shmat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_shmctl]	=	{"shmctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
*/
		[__NR_dup]	=	{"dup", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_dup2]	=	{"dup2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pause]	=	{"pause", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_nanosleep]	=	{"nanosleep", 2, {PTR, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_getitimer]	=	{"getitimer", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_alarm]	=	{"alarm", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setitimer]	=	{"setitimer", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getpid]	=	{"getpid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sendfile]	=	{"sendfile64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_socket]	=	{"socket", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_connect]	=	{"connect", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_accept4]	=	{"accept", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sendto]	=	{"sendto", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_recvfrom]	=	{"recvfrom", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sendmsg]	=	{"sendmsg", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_recvmsg]	=	{"recvmsg", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_shutdown]	=	{"shutdown", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_bind]	=	{"bind", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_listen]	=	{"listen", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getsockname]	=	{"getsockname", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getpeername]	=	{"getpeername", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_socketpair]	=	{"socketpair", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setsockopt]	=	{"setsockopt", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getsockopt]	=	{"getsockopt", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_clone]	=	{"clone", 4, {INT, PTR, INT, PTR, 0, 0}, INT, -1, general},
		[__NR_fork]	=	{"fork", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_vfork]	=	{"vfork", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_execve]	=	{"execve", 0, {0, 0, 0, 0, 0, 0}, INT, -1, sys_execve_32},
		[__NR_exit]	=	{"exit", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_wait4]	=	{"wait4", 4, {INT, PTR, INT, PTR, 0, 0}, LONG, 0, general},
		[__NR_kill]	=	{"kill", 2, {INT, SIG, 0, 0, 0, 0}, INT, 0, general},
		[__NR_uname]	=	{"newuname", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
/*
		[__NR_semget]	=	{"semget", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_semop]	=	{"semop", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_semctl]	=	{"semctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_shmdt]	=	{"shmdt", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_msgget]	=	{"msgget", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_msgsnd]	=	{"msgsnd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_msgrcv]	=	{"msgrcv", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_msgctl]	=	{"msgctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
*/
		[__NR_fcntl]	=	{"fcntl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_flock]	=	{"flock", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fsync]	=	{"fsync", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fdatasync]	=	{"fdatasync", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_truncate]	=	{"truncate", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_ftruncate]	=	{"ftruncate", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getdents]	=	{"getdents", 3, {LONG, PTR, LONG, 0, 0, 0}, INT, -1, general},
		[__NR_getcwd]	=	{"getcwd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_chdir]	=	{"chdir", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fchdir]	=	{"fchdir", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_rename]	=	{"rename", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mkdir]	=	{"mkdir", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_rmdir]	=	{"rmdir", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_creat]	=	{"creat", 2, {STR, INT, 0, 0, 0, 0}, 0, -1, general},
		[__NR_link]	=	{"link", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_unlink]	=	{"unlink", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_symlink]	=	{"symlink", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_readlink]	=	{"readlink", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_chmod]	=	{"chmod", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fchmod]	=	{"fchmod", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_chown]	=	{"chown", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fchown]	=	{"fchown", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_lchown]	=	{"lchown", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_umask]	=	{"umask", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_gettimeofday]	=	{"gettimeofday", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getrlimit]	=	{"getrlimit", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_getrusage]	=	{"getrusage", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sysinfo]	=	{"sysinfo", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_times]	=	{"times", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_ptrace]	=	{"ptrace", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getuid]	=	{"getuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_syslog]	=	{"syslog", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getgid]	=	{"getgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setuid]	=	{"setuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setgid]	=	{"setgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_geteuid]	=	{"geteuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getegid]	=	{"getegid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setpgid]	=	{"setpgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getppid]	=	{"getppid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getpgrp]	=	{"getpgrp", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setsid]	=	{"setsid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setreuid]	=	{"setreuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setregid]	=	{"setregid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getgroups]	=	{"getgroups", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setgroups]	=	{"setgroups", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setresuid]	=	{"setresuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getresuid]	=	{"getresuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setresgid]	=	{"setresgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getresgid]	=	{"getresgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getpgid]	=	{"getpgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setfsuid]	=	{"setfsuid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setfsgid]	=	{"setfsgid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getsid]	=	{"getsid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_capget]	=	{"capget", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_capset]	=	{"capset", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_rt_sigpending]	=	{"rt_sigpending", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_rt_sigtimedwait]	=	{"rt_sigtimedwait", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_rt_sigqueueinfo]	=	{"rt_sigqueueinfo", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_rt_sigsuspend]	=	{"rt_sigsuspend", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sigaltstack]	=	{"sigaltstack", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_utime]	=	{"utime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mknod]	=	{"mknod", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_personality]	=	{"personality", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_ustat]	=	{"ustat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_statfs]	=	{"statfs", 2, {STR, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_fstatfs]	=	{"fstatfs", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_sysfs]	=	{"sysfs", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getpriority]	=	{"getpriority", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setpriority]	=	{"setpriority", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_setparam]	=	{"sched_setparam", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_getparam]	=	{"sched_getparam", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_setscheduler]=	{"sched_setscheduler", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_getscheduler]=	{"sched_getscheduler", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_get_priority_max]=	{"sched_get_priority_max", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_get_priority_min]=	{"sched_get_priority_min", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_rr_get_interval]=	{"sched_rr_get_interval", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mlock]	=	{"mlock", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_munlock]	=	{"munlock", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mlockall]	=	{"mlockall", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_munlockall]	=	{"munlockall", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_vhangup]	=	{"vhangup", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_modify_ldt]	=	{"modify_ldt", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pivot_root]	=	{"pivot_root", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR__sysctl]	=	{"sysctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_prctl]	=	{"prctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_arch_prctl]	=	{"arch_prctl", 2, {INT, LONG, 0, 0, 0, 0}, INT, -1, general},
		[__NR_adjtimex]	=	{"adjtimex", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setrlimit]	=	{"setrlimit", 2, {INT, PTR, 0, 0, 0, 0}, INT, -1, general},
		[__NR_chroot]	=	{"chroot", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sync]	=	{"sync", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_acct]	=	{"acct", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_settimeofday]	=	{"settimeofday", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mount]	=	{"mount", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_umount2]	=	{"umount", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_swapon]	=	{"swapon", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_swapoff]	=	{"swapoff", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_reboot]	=	{"reboot", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sethostname]	=	{"sethostname", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setdomainname]	=	{"setdomainname", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_iopl]	=	{"iopl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_ioperm]	=	{"ioperm", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_init_module]	=	{"init_module", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_delete_module]	=	{"delete_module", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_quotactl]	=	{"quotactl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_gettid]	=	{"gettid", 0, {0, 0, 0, 0, 0, 0}, INT, 0, general},
		[__NR_readahead]	=	{"readahead", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setxattr]	=	{"setxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_lsetxattr]	=	{"lsetxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fsetxattr]	=	{"fsetxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getxattr]	=	{"getxattr", 4, {STR, STR, PTR, LONG, 0, 0}, INT, -1, general},
		[__NR_lgetxattr]	=	{"lgetxattr", 4, {STR, STR, PTR, LONG, 0, 0}, INT, -1, general},
		[__NR_fgetxattr]	=	{"fgetxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_listxattr]	=	{"listxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_llistxattr]	=	{"llistxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_flistxattr]	=	{"flistxattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_removexattr]	=	{"removexattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_lremovexattr]	=	{"lremovexattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fremovexattr]	=	{"fremovexattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_tkill]	=	{"tkill", 2, {INT, SIG, 0, 0, 0, 0}, INT, -1, general},
		[__NR_time]	=	{"time", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_futex]	=	{"futex", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_setaffinity]=	{"sched_setaffinity", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_getaffinity]=	{"sched_getaffinity", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_io_setup]	=	{"io_setup", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_io_destroy]	=	{"io_destroy", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_io_getevents]	=	{"io_getevents", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_io_submit]	=	{"io_submit", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_io_cancel]	=	{"io_cancel", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_lookup_dcookie]	=	{"lookup_dcookie", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_epoll_create]	=	{"epoll_create", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_remap_file_pages]=	{"remap_file_pages", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getdents64]	=	{"getdents64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_set_tid_address]	=	{"set_tid_address", 1, {PTR, 0, 0, 0, 0, 0}, LONG, 0, general},
		[__NR_restart_syscall]	=	{"restart_syscall", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_stime]	=	{"semtimedop", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fadvise64]	=	{"fadvise64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_timer_create]	=	{"timer_create", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_timer_settime]	=	{"timer_settime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_timer_gettime]	=	{"timer_gettime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_timer_getoverrun]=	{"timer_getoverrun", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_timer_delete]	=	{"timer_delete", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_clock_settime]	=	{"clock_settime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_clock_gettime]	=	{"clock_gettime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_clock_getres]	=	{"clock_getres", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_clock_nanosleep]	=	{"clock_nanosleep", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_exit_group]	=	{"exit_group", 1, {INT, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_epoll_wait]	=	{"epoll_wait", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_epoll_ctl]	=	{"epoll_ctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_tgkill]	=	{"tgkill", 3, {INT, INT, SIG, 0, 0, 0}, INT, -1, general},
		[__NR_utimes]	=	{"utimes", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mbind]	=	{"mbind", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_set_mempolicy]	=	{"set_mempolicy", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_get_mempolicy]	=	{"get_mempolicy", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mq_open]	=	{"mq_open", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mq_unlink]	=	{"mq_unlink", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mq_timedsend]	=	{"mq_timedsend", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mq_timedreceive]	=	{"mq_timedreceive", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mq_notify]	=	{"mq_notify", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mq_getsetattr]	=	{"mq_getsetattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_kexec_load]	=	{"kexec_load", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_waitid]	=	{"waitid", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_add_key]	=	{"add_key", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_request_key]	=	{"request_key", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_keyctl]	=	{"keyctl", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_ioprio_set]	=	{"ioprio_set", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_ioprio_get]	=	{"ioprio_get", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_inotify_init]	=	{"inotify_init", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_inotify_add_watch] =	{"inotify_add_watch", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_inotify_rm_watch]=	{"inotify_rm_watch", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_migrate_pages]	=	{"migrate_pages", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_openat]	=	{"openat", 4, {INT, STR, INT, INT, 0, 0}, INT, -1, general},
		[__NR_mkdirat]	=	{"mkdirat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mknodat]	=	{"mknodat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fchownat]	=	{"fchownat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_futimesat]	=	{"futimesat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_oldfstat]	=	{"newfstatat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_unlinkat]	=	{"unlinkat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_renameat]	=	{"renameat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_linkat]	=	{"linkat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_symlinkat]	=	{"symlinkat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_readlinkat]	=	{"readlinkat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fchmodat]	=	{"fchmodat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_faccessat]	=	{"faccessat", 4, {INT, STR, INT, INT, 0}, INT, -1, general},
		[__NR_pselect6]	=	{"pselect6", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_ppoll]	=	{"ppoll", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_unshare]	=	{"unshare", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_set_robust_list]	=	{"set_robust_list", 2, {INT, PTR, LONG, 0, 0, 0}, LONG, -1, general},
		[__NR_get_robust_list]	=	{"get_robust_list", 3, {PTR, LONG, 0, 0, 0, 0}, LONG, -1, general},
		[__NR_splice]	=	{"splice", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_tee]	=	{"tee", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sync_file_range]	=	{"sync_file_range", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_vmsplice]	=	{"vmsplice", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_move_pages]	=	{"move_pages", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_utimensat]	=	{"utimensat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_epoll_pwait]	=	{"epoll_pwait", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_signalfd]	=	{"signalfd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_timerfd_create]	=	{"timerfd_create", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_eventfd]	=	{"eventfd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fallocate]	=	{"fallocate", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_timerfd_settime]	=	{"timerfd_settime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_timerfd_gettime]	=	{"timerfd_gettime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_signalfd4]	=	{"signal", 2, {SIG, PTR, 0, 0, 0, 0}, PTR, -1, general},
		[__NR_eventfd2]	=	{"eventfd2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_epoll_create1]	=	{"epoll_create1", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_dup3]	=	{"dup3", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pipe2]	=	{"pipe2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_inotify_init1]	=	{"inotify_init1", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_preadv]	=	{"preadv", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pwritev]	=	{"pwritev", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_rt_tgsigqueueinfo]=	{"rt_tgsigqueueinfo", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_perf_event_open]	=	{"perf_event_open", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_recvmmsg]	=	{"recvmmsg", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fanotify_init]	=	{"fanotify_init", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_fanotify_mark]	=	{"fanotify_mark", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_prlimit64]	=	{"prlimit64", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_name_to_handle_at]=	{"name_to_handle_at", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_open_by_handle_at]=	{"open_by_handle_at", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_clock_adjtime]	=	{"clock_adjtime", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_syncfs]	=	{"syncfs", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sendmmsg]	=	{"sendmmsg", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_setns]	=	{"setns", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getcpu]	=	{"getcpu", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_process_vm_readv]=	{"process_vm_readv", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_process_vm_writev]=	{"process_vm_writev", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_kcmp]	=	{"kcmp", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_finit_module]	=	{"finit_module", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_setattr]	=	{"sched_setattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_sched_getattr]	=	{"sched_getattr", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_renameat2]	=	{"renameat2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
/*
		[__NR_seccomp]	=	{"seccomp", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_getrandom]	=	{"getrandom", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_memfd_create]	=	{"memfd_create", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_kexec_file_load]	=	{"kexec_file_load", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_bpf]	=	{"bpf", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_execveat]	=	{"execveat", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_userfaultfd]	=	{"userfaultfd", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_membarrier]	=	{"membarrier", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_mlock2]	=	{"mlock2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_copy_file_range]	=	{"copy_file_range", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_preadv2]	=	{"preadv2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pwritev2]	=	{"pwritev2", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pkey_mprotect]	=	{"pkey_mprotect", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pkey_alloc]	=	{"pkey_alloc", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_pkey_free]	=	{"pkey_free", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_statx]	=	{"statx", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_io_pgetevents]	=	{"io_pgetevents", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
		[__NR_rseq]	=	{"rseq", 0, {0, 0, 0, 0, 0, 0}, 0, 0, general},
*/
};
uint32_t syscalls_32_value = COUNT_OF(syscalls_32);
