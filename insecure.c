#define FUSE_USE_VERSION 26
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fuse.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>
#include <sqlite3.h>

struct insecure_state {
    char *mount_point; // mount point path
    int mount_point_len;
    char *backend_point; // backend path
    int backend_point_len;
    sqlite3 *db;
};

#define FS_DATA ((struct insecure_state *) fuse_get_context()->private_data)

int insecure_getattr (const char *path, struct stat *stbuf) {
    char *full_path;
    int ret;

    full_path = (char *) calloc (strlen(path) + FS_DATA->backend_point_len + 1, 1);
    strcpy (full_path, FS_DATA->backend_point);
    strcat (full_path, path);

    ret = stat (full_path, stbuf);
    free (full_path);

    return ret;
}

void *insecure_init (struct fuse_conn_info *conn) {
    printf("init\n");
    return FS_DATA;
}

int insecure_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    printf ("readdir on %s\n", path);

    gchar *full_path = g_build_path ("/", FS_DATA->backend_point, path, NULL);
    struct dirent *de;
    DIR *dp;
    dp = opendir (full_path);
    g_free (full_path);

    while (NULL != (de = readdir (dp))) {
        if (0 != filler (buf, de->d_name, NULL, 0)) {
            return -ENOMEM;
        }
    }

    return 0;
}

int insecure_open (const char *path, struct fuse_file_info *fi) {
    printf ("open\n");
    gchar *full_path = g_build_path ("/", FS_DATA->backend_point, path, NULL);
    int fd = open (full_path, fi->flags);
    if (fd < 0) {
        return -errno;
    }
    fi->fh = (unsigned int) fd;
    printf ("handle %d\n", fd);
    return 0;
}

int insecure_read (const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    printf("read\n");
    if ((off_t)-1 == lseek (fi->fh, offset, SEEK_SET)) {
        return -errno;
    }

    size_t bytes_read = read (fi->fh, buf, size);
    if (-1 == bytes_read) return -errno;

    return bytes_read;
}



struct fuse_operations insecure_op = {
    .getattr = insecure_getattr,
    .readdir = insecure_readdir,
    .init = insecure_init,
    .open = insecure_open,
    .read = insecure_read,
};

int main (int argc, char *argv[]) {
    struct insecure_state *state;
    int res;

    state = (struct insecure_state *) calloc (sizeof(struct insecure_state), 1);

    if (argc < 2) {
        printf("need more arguments\n");
        exit(1);
    }

    state->mount_point = argv[1];
    state->backend_point = argv[2];
    state->mount_point_len = strlen (state->mount_point);
    state->backend_point_len = strlen (state->backend_point);

    int f_argc = 5;
    char *f_argv[] = {argv[0], "-f", "-o", "nonempty", state->mount_point};

    res = fuse_main (f_argc, f_argv, &insecure_op, state);
    printf ("fuse_main returned %d\n", res);
}
