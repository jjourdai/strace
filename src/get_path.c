#include "strace.h"
#include "colors.h"

static char *get_next_path(char *path)
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

static char 	*local_binary(char *bin_name)
{
	char	buf[PATH_MAX + 1];
	char	*concat;
	struct stat buf_st;

	getcwd(buf, PATH_MAX);	
	asprintf(&concat, "%s/%s", buf, bin_name);
	if (stat(concat, &buf_st) == -1)
		return (NULL);
	else
		return (concat);
}

static char	*search_binary_in_path(char *binary_name)
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
		if (test == NULL)
			if ((concat = local_binary(binary_name)) != NULL)
				return (concat);
		if (test == NULL) {
			fprintf(stderr, RED_TEXT("%s: Command not found\n"), binary_name); exit(EXIT_FAILURE);
		}
		return (concat);
	}
}

char	*get_binary_path(char *dest)
{
	char *bin;

	if (ft_strncmp(dest, "./", 2) == 0) 	/* local path */
		bin = local_binary(dest);
	else if (dest[0] == '/')				/* obsolut path */
		bin = dest;
	else 											/* relative path */ 
		bin = search_binary_in_path(dest);
	return (bin);
}
