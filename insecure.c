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


/// Inserts file path to database and returns string containing backpath
///
///
static gchar *insecure_insert_name_to_db (const char *path) {
    struct insecure_state *state = FS_DATA;
    int rc;

    sqlite3_stmt *stmt_ins;
    sqlite3_prepare_v2 (state->db,
        "INSERT OR IGNORE INTO fit (fname, parent) SELECT ?, id FROM fit WHERE fname=?;",
        -1,
        &stmt_ins,
        NULL);
    sqlite3_bind_text (stmt_ins, 1, path, -1, SQLITE_TRANSIENT);
    gchar *parent_path = g_path_get_dirname (path);
    sqlite3_bind_text (stmt_ins, 2, parent_path, -1, SQLITE_TRANSIENT);
    g_free (parent_path);

    rc = sqlite3_step (stmt_ins);
    sqlite3_finalize (stmt_ins);

    sqlite3_int64 rowid = sqlite3_last_insert_rowid (state->db);
    sqlite3_stmt *stmt_sel;
    sqlite3_prepare_v2 (state->db,
        "SELECT fit.id, p.backname FROM fit, fit as p WHERE fit.ROWID=? AND p.id=fit.parent",
        -1,
        &stmt_sel,
        NULL);
    sqlite3_bind_int64 (stmt_sel, 1, rowid);
    rc = sqlite3_step (stmt_sel);
    if (SQLITE_ROW != rc) {
        sqlite3_finalize (stmt_sel);
        return NULL;
    }

    GString *backend_name = g_string_new (NULL);
    g_string_printf (backend_name, "prefix_%d", sqlite3_column_int (stmt_sel, 0));

    gchar *backend_path = g_build_path ("/", (gchar *)sqlite3_column_text (stmt_sel, 1), backend_name->str, NULL);

    sqlite3_stmt *stmt_upd;
    sqlite3_prepare_v2 (state->db,
        "UPDATE fit SET backname = ? WHERE ROWID=?",
        -1,
        &stmt_upd,
        NULL);
    sqlite3_bind_text (stmt_upd, 1, backend_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64 (stmt_upd, 2, rowid);
    sqlite3_step (stmt_upd);
    sqlite3_finalize (stmt_upd);

    gchar *full_backend_path = g_build_path ("/", state->backend_point, backend_path, NULL);

    g_free (backend_path);
    g_string_free (backend_name, TRUE);

    sqlite3_finalize (stmt_sel);
    return full_backend_path;
}

int insecure_getattr (const char *path, struct stat *stbuf) {
    int ret;
    int rc;
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
        ret = -ENOENT;
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

    while (SQLITE_ROW == sqlite3_step (stmt)) {
        gchar *basename = g_path_get_basename ((char *)sqlite3_column_text (stmt, 0));
        rc = filler (buf, basename, NULL, 0);
        g_free (basename);

        if (0 != rc) {
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

int insecure_mknod (const char *path, mode_t mode, dev_t dev) {
    printf ("mknod %s, mode %06o\n", path, mode);
    int ret;

    if (S_ISREG(mode)) {
        gchar *back_path = insecure_insert_name_to_db (path);
        if (NULL == back_path)
            return -ENOENT;

        ret = open(back_path, O_CREAT | O_EXCL | O_WRONLY, mode);
        g_free (back_path);

        return ret;
    }

    return -ENOSYS;
}

int insecure_mkdir (const char *path, mode_t mode) {
    printf ("mkdir %s, mode %06o\n", path, mode);
    int ret;

    gchar *back_path = insecure_insert_name_to_db (path);
    if (NULL == back_path)
        return -ENOENT;

    ret = mkdir (back_path, mode);
    g_free (back_path);

    return ret;
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

int insecure_write (const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    printf("write\n");

    return -EACCES;
}

int insecure_access(const char *path, int mask) {
    printf ("access to '%s', mask %06o\n", path, mask);
    struct insecure_state *state = FS_DATA;
    sqlite3_stmt *stmt;
    int rc;
    int ret;

    rc = sqlite3_prepare_v2 (state->db, "SELECT backname FROM fit WHERE fname=?;", -1, &stmt, NULL);
    rc = sqlite3_bind_text (stmt, 1, path, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step (stmt);
    if (SQLITE_ROW == rc) {
        gchar *full_path = g_build_path ("/", state->backend_point, sqlite3_column_text (stmt, 0), NULL);
        ret = access (full_path, mask);
        g_free (full_path);
    } else {
        ret = -ENOENT;
    }

    sqlite3_finalize (stmt);

    return ret;
}


struct fuse_operations insecure_op = {
    .getattr = insecure_getattr,
    .mknod = insecure_mknod,
    .mkdir = insecure_mkdir,
    .readdir = insecure_readdir,
    .init = insecure_init,
    .open = insecure_open,
    .read = insecure_read,
    .write = insecure_write,
    .access = insecure_access,
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
