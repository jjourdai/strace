#include "strace.h"

const char *signal_macro[] = {
  [1] = "SIGHUP",
  [2] = "SIGINT",
  [3] = "SIGQUIT",
  [4] = "SIGKILL",
  [5] = "SIGTRAP",
  [6] = "SIGABRT",
  [7] = "SIGBUS",
  [8] = "SIGFPE",
  [9] = "SIGKILL",
  [10] = "SIGUSR1",
  [11] = "SIGSEGV",
  [12] = "SIGUSR2",
  [13] = "SIGPIPE",
  [14] = "SIGALRM",
  [15] = "SIGTERM",
  [16] = "SIGSTKFLT",
  [17] = "SIGCHLD",
  [18] = "SIGCONT",
  [19] = "SIGSTOP",
  [20] = "SIGTSTP",
  [21] = "SIGTTIN",
  [22] = "SIGTTOU",
  [23] = "SIGTURG",
  [24] = "SIGXCPU",
  [25] = "SIGXFSZ",
  [26] = "SIGVTALRM",
  [27] = "SIGPROF",
  [28] = "SIGWINCH",
  [29] = "SIGIO",
  [30] = "SIGPOLL",
  [31] = "SIGSYS",
  [32] = "SIGRTMIN",
};

void	block_signal(sigset_t *blockSet)
{

	sigemptyset(blockSet);
	sigaddset(blockSet, SIGHUP);
	sigaddset(blockSet, SIGINT);
	sigaddset(blockSet, SIGQUIT);
	sigaddset(blockSet, SIGPIPE);
	sigaddset(blockSet, SIGTERM);
	//__ASSERTI(-1, sigprocmask(SIG_BLOCK, blockSet, NULL), "Sigprocmask");
}

void	release_signal(sigset_t *empty_set)
{
	sigemptyset(empty_set);
//	__ASSERTI(-1, sigprocmask(SIG_SETMASK, &empty_set, NULL), "Sigprocmask");
}

void	signal_handler(int signum)
{

}

void	init_sigaction(int signum)
{
	struct sigaction sa = {
		.sa_handler = SIG_DFL,
		//.sa_flags = SA_SIGINFO,
	};
	sigemptyset(&sa.sa_mask);

	sigaction(signum, &sa, NULL);
}

void	init_signal(void)
{
	struct sigaction sa = {
		.sa_handler = SIG_IGN,
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
