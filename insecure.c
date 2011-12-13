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

static const char *sql_create_tables =
    "CREATE TABLE IF NOT EXISTS fit (id INTEGER PRIMARY KEY, fname TEXT, backname TEXT, parent INTEGER); "
    "CREATE UNIQUE INDEX IF NOT EXISTS fit_fname ON fit (fname); "
    "INSERT OR IGNORE INTO fit (id, fname, parent, backname) VALUES (1, '/', 0, '/'); ";

#define FS_DATA ((struct insecure_state *) fuse_get_context()->private_data)

int insecure_getattr (const char *path, struct stat *stbuf) {
    int ret;
    int rc;

    gchar *full_path;
    struct insecure_state *state = FS_DATA;

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2 (state->db, "SELECT backname FROM fit WHERE fname=?;", -1, &stmt, NULL);
    // printf ("sqlite3_prepare rc = %d\n", rc);
    rc = sqlite3_bind_text (stmt, 1, path, -1, SQLITE_TRANSIENT);
    // printf ("sqlite3_bind_text rc = %d\n", rc);
    rc = sqlite3_step (stmt);
    // printf ("sqlite3_step rc = %d\n", rc);

    if (SQLITE_ROW == rc) {
        printf ("there is a file named %s, ", path);
        printf ("and it backed at file %s\n", sqlite3_column_text (stmt, 0));

        gchar *full_path = g_build_path ("/", state->backend_point, sqlite3_column_text (stmt, 0), NULL);
        ret = stat (full_path, stbuf);
        g_free (full_path);
    } else {
        printf ("there is no file named %s\n", path);
        ret = -1;
        errno = ENOENT;
    }

    sqlite3_finalize (stmt);

    return ret;
}

void *insecure_init (struct fuse_conn_info *conn) {
    printf("init\n");

    struct insecure_state *state = FS_DATA;
    int rc;

    gchar *db_name = g_build_path ("/", state->backend_point, ".filenames.db", NULL);
    rc = sqlite3_open (db_name, &state->db);
    printf ("db_name = %s\n", db_name);
    printf ("rc = %d\n", rc);
    // FIXME: error handling
    rc = sqlite3_exec (state->db, sql_create_tables, NULL, 0, NULL);
    printf ("rc = %d\n", rc);

    return FS_DATA;
}

int insecure_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    printf ("readdir on %s\n", path);
    struct insecure_state *state = FS_DATA;
    int rc;

    sqlite3_stmt *stmt;

    rc = sqlite3_prepare_v2 (state->db,
        "SELECT fit.fname FROM fit, fit as p WHERE p.fname=? AND p.id=fit.parent",
        -1,     // nByte
        &stmt,
        NULL    // pzTail
    );

    rc = sqlite3_bind_text (stmt, 1, path, -1, SQLITE_TRANSIENT);

    filler (buf, ".", NULL, 0);
    filler (buf, "..", NULL, 0);

    while (SQLITE_ROW == (rc = sqlite3_step (stmt))) {
        if (0 != filler (buf, (char *)sqlite3_column_text (stmt, 0), NULL, 0)) {
            sqlite3_finalize (stmt);
            return -ENOMEM;
        }
    }
    sqlite3_finalize (stmt);

    return 0;
}

int insecure_open (const char *path, struct fuse_file_info *fi) {
    printf ("open\n");
    /*
    gchar *full_path = g_build_path ("/", FS_DATA->backend_point, path, NULL);
    int fd = open (full_path, fi->flags);
    if (fd < 0) {
        return -errno;
    }
    fi->fh = (unsigned int) fd;
    printf ("handle %d\n", fd);
    */


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
