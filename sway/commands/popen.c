#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include "sway/commands.h"
#include "sway/config.h"
#include "sway/tree/container.h"
#include "sway/tree/root.h"
#include "sway/tree/workspace.h"
#include "log.h"
#include "stringop.h"

static struct open_pipe {
	char *id;
	int fd;
} *open_pipes;

static int open_pipes_cnt;

static int handler_compare(const void *_key, const void *_element) {
	const char *key = _key;
	const struct open_pipe *element = _element;
	return strcasecmp(key, element->id);
}

struct cmd_results *cmd_popen(int argc, char **argv) {
	struct cmd_results *error = NULL;
	if (!config->active || config->validating) {
		return cmd_results_new(CMD_DEFER, NULL);
	}
	if ((error = checkarg(argc, argv[-1], EXPECTED_AT_LEAST, 2))) {
		return error;
	}

	char *name = argv[0];

	char *tmp;

	if (argc == 2 && (argv[1][0] == '\'' || argv[1][0] == '"')) {
		tmp = strdup(argv[1]);
		strip_quotes(tmp);
	} else {
		tmp = join_args(argv + 1, argc - 1);
	}

	// Put argument into cmd array
	char cmd[4096];
	strncpy(cmd, tmp, sizeof(cmd) - 1);
	cmd[sizeof(cmd) - 1] = 0;
	free(tmp);
	sway_log(SWAY_DEBUG, "Executing %s", cmd);

	int pid_fd[2];
	if (pipe(pid_fd) != 0) {
		sway_log(SWAY_ERROR, "Unable to create pipe for fork");
	}

	int stdin_fd[2];
	if (pipe(stdin_fd) != 0) {
		sway_log(SWAY_ERROR, "Unable to create pipe for fork");
	}

	pid_t pid, child;
	// Fork process
	if ((pid = fork()) == 0) {
		// Fork child process again
		setsid();
		sigset_t set;
		sigemptyset(&set);
		sigprocmask(SIG_SETMASK, &set, NULL);
		close(pid_fd[0]);
		close(stdin_fd[1]);
		if ((child = fork()) == 0) {
			close(pid_fd[1]);
			dup2(stdin_fd[0], 0);
			close(stdin_fd[0]);
			execl("/bin/sh", "/bin/sh", "-c", cmd, (void *)NULL);
			_exit(0);
		}
		ssize_t s = 0;
		while ((size_t)s < sizeof(pid_t)) {
			s += write(pid_fd[1], ((uint8_t *)&child) + s, sizeof(pid_t) - s);
		}
		close(pid_fd[1]);
		_exit(0); // Close child process
	} else if (pid < 0) {
		close(pid_fd[0]);
		close(pid_fd[1]);
		return cmd_results_new(CMD_FAILURE, "fork() failed");
	}
	close(pid_fd[1]); // close write
	close(stdin_fd[0]); // close write
	ssize_t s = 0;
	while ((size_t)s < sizeof(pid_t)) {
		s += read(pid_fd[0], ((uint8_t *)&child) + s, sizeof(pid_t) - s);
	}
	close(pid_fd[0]);
	// cleanup child process
	waitpid(pid, NULL, 0);
	if (child > 0) {
		sway_log(SWAY_DEBUG, "Child process created with pid %d", child);
		root_record_workspace_pid(child);
	} else {
		close(stdin_fd[1]);
		return cmd_results_new(CMD_FAILURE, "Second fork() failed");
	}

	fcntl(stdin_fd[1], F_SETFL, O_NONBLOCK);

	struct open_pipe *new_open_pipes = malloc(
		sizeof(struct open_pipe) * (open_pipes_cnt + 1));

	for (int i = 0; i < open_pipes_cnt; i++) {
		int x = strcasecmp(open_pipes[i].id, name);
		if (x < 0) {
			new_open_pipes[i] = open_pipes[i];
		} else if (x == 0) {
			new_open_pipes[i].id = open_pipes[i].id;
			close(open_pipes[i].fd);
			new_open_pipes[i].fd = stdin_fd[1];
			memcpy(new_open_pipes + i + 1, open_pipes + i + 1,
				sizeof(struct open_pipe) * (open_pipes_cnt - i - 1));
			goto added;
		} else {
			new_open_pipes[i].id = strdup(name);
			new_open_pipes[i].fd = stdin_fd[1];
			memcpy(new_open_pipes + i + 1, open_pipes + i,
				sizeof(struct open_pipe) * (open_pipes_cnt - i));
			open_pipes_cnt++;
			goto added;
		}
	}

	new_open_pipes[open_pipes_cnt].id = strdup(name);
	new_open_pipes[open_pipes_cnt].fd = stdin_fd[1];
	open_pipes_cnt++;

added:
	free(open_pipes);
	open_pipes = new_open_pipes;

	return cmd_results_new(CMD_SUCCESS, NULL);
}

struct cmd_results *cmd_pwrite(int argc, char **argv) {
	struct cmd_results *error = NULL;
	if (!config->active || config->validating) {
		return cmd_results_new(CMD_DEFER, NULL);
	}
	if ((error = checkarg(argc, argv[-1], EXPECTED_AT_LEAST, 2))) {
		return error;
	}

	struct open_pipe *p = bsearch(argv[0], open_pipes,
		open_pipes_cnt, sizeof(struct open_pipe), handler_compare);

	if (!p || p->fd < 0) {
		return cmd_results_new(CMD_FAILURE, "No such pipe");
	}

	char *cmd;

	if (argc == 2 && (argv[1][0] == '\'' || argv[1][0] == '"')) {
		cmd = strdup(argv[1]);
		strip_quotes(cmd);
	} else {
		cmd = join_args(argv + 1, argc - 1);
	}

	int cmdsize = strlen(cmd);
	cmd[cmdsize] = '\n';
	cmdsize++;

	char *ptr = cmd;

	do {
		int ret = write(p->fd, ptr, cmdsize);
		if (ret > 0) {
			ptr += ret;
			cmdsize -= ret;
		} else {
			int write_errno = errno;
			close(p->fd);
			p->fd = -1;
			return cmd_results_new(CMD_FAILURE,
				"Pipe write: %s", strerror(write_errno));
		}
	} while (cmdsize);

	free(cmd);

	return cmd_results_new(CMD_SUCCESS, NULL);
}
