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
    time_t last_flush;
};

static const char *sql_create_tables =
    "CREATE TABLE IF NOT EXISTS fit (id INTEGER PRIMARY KEY, fname TEXT, backname TEXT, parent INTEGER); "
    "CREATE UNIQUE INDEX IF NOT EXISTS fit_fname ON fit (fname); "
    "INSERT OR IGNORE INTO fit (id, fname, parent, backname) VALUES (1, '/', 0, '/'); ";

#define FS_DATA ((struct insecure_state *) fuse_get_context()->private_data)

static void insecure_flush_tables () {
    struct insecure_state *state = FS_DATA;
    static int counter = 0;

    counter ++;
    time_t current = time(NULL);
    if ((counter > 4000) || (current - state->last_flush > 2)) {
        sqlite3_exec (FS_DATA->db, "COMMIT; BEGIN TRANSACTION;", NULL, NULL, NULL);
        counter = 0;
        state->last_flush = current;
    }
}

/// Inserts file path to database and returns string containing backpath
///
/// caller must free returned string with g_free()
static gchar *insecure_insert_name_to_db (const char *path) {
    struct insecure_state *state = FS_DATA;
    int rc;

    insecure_flush_tables ();

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

static gchar *insecure_get_backname (const gchar *fname) {
    struct insecure_state *state = FS_DATA;
    sqlite3_stmt *stmt;
    int rc;

    insecure_flush_tables ();

    sqlite3_prepare_v2 (state->db, "SELECT backname FROM fit WHERE fname=?", -1, &stmt, NULL);
    sqlite3_bind_text (stmt, 1, fname, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step (stmt);
    if (SQLITE_ROW != rc) {
        sqlite3_finalize (stmt);
        return NULL;
    }
    gchar *ret = g_strdup ((gchar *)sqlite3_column_text (stmt, 0));
    sqlite3_finalize (stmt);
    return ret;
}

int insecure_getattr (const char *path, struct stat *stbuf) {
    int ret;
    int rc;
    struct insecure_state *state = FS_DATA;

    insecure_flush_tables ();

    printf ("stat '%s'\n", path);

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2 (state->db, "SELECT backname FROM fit WHERE fname=?;", -1, &stmt, NULL);
    // printf ("sqlite3_prepare rc = %d\n", rc);
    rc = sqlite3_bind_text (stmt, 1, path, -1, SQLITE_TRANSIENT);
    // printf ("sqlite3_bind_text rc = %d\n", rc);
    rc = sqlite3_step (stmt);
    // printf ("sqlite3_step rc = %d\n", rc);

    if (SQLITE_ROW == rc) {
        printf ("+ '%s', '%s'\n", path, sqlite3_column_text (stmt, 0));

        gchar *full_path = g_build_path ("/", state->backend_point, sqlite3_column_text (stmt, 0), NULL);
        ret = lstat (full_path, stbuf);
        g_free (full_path);
    } else {
        printf ("- '%s'\n", path);
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

    sqlite3_exec (state->db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    return FS_DATA;
}

void insecure_destroy (void *p) {
    printf ("shutting down\n");
    sqlite3_close (FS_DATA->db);
}

int insecure_readdir (const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    printf ("readdir on %s\n", path);
    struct insecure_state *state = FS_DATA;
    int rc;

    insecure_flush_tables ();

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
    printf ("open '%s'\n", path);
    insecure_flush_tables ();

    gchar *backname = insecure_get_backname (path);
    gchar *full_backname = g_build_path ("/", FS_DATA->backend_point, backname, NULL);

    int fd = open (full_backname, fi->flags);

    g_free (full_backname);
    g_free (backname);

    if (fd < 0) return -errno;

    fi->fh = fd;
    return 0;
}

int insecure_release (const char *path, struct fuse_file_info *fi) {
    printf ("close '%s'\n", path);
    insecure_flush_tables ();

    int ret = close (fi->fh);

    return ret;
}

int insecure_mknod (const char *path, mode_t mode, dev_t dev) {
    printf ("mknod %s, mode %06o\n", path, mode);
    insecure_flush_tables ();
    int fd;

    if (S_ISREG(mode)) {
        gchar *back_path = insecure_insert_name_to_db (path);
        if (NULL == back_path)
            return -ENOENT;

        fd = open(back_path, O_CREAT | O_EXCL | O_WRONLY, mode);
        g_free (back_path);

        if (fd < 0) return -errno;

        return close (fd);
    }

    return -EACCES;
}

int insecure_mkdir (const char *path, mode_t mode) {
    printf ("mkdir %s, mode %06o\n", path, mode);
    insecure_flush_tables ();
    int ret;

    gchar *back_path = insecure_insert_name_to_db (path);
    if (NULL == back_path)
        return -ENOENT;

    ret = mkdir (back_path, mode);
    g_free (back_path);

    return ret;
}

int insecure_read (const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    printf("read of %s\n", path);
    insecure_flush_tables ();
    if ((off_t)-1 == lseek (fi->fh, offset, SEEK_SET)) {
        return -errno;
    }

    size_t bytes_read = read (fi->fh, buf, size);
    if (-1 == bytes_read) return -errno;

    return bytes_read;
}

int insecure_write (const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    printf("write of '%s'\n", path);
    insecure_flush_tables ();
    if ((off_t)-1 == lseek (fi->fh, offset, SEEK_SET)) {
        return -errno;
    }

    size_t bytes_written = write (fi->fh, buf, size);
    if (-1 == bytes_written) return -errno;

    return bytes_written;
}

int insecure_access(const char *path, int mask) {
    printf ("access to '%s', mask %06o\n", path, mask);
    insecure_flush_tables ();
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

int insecure_truncate (const char *path, off_t newsize) {
    printf ("truncate\n");
    insecure_flush_tables ();
    struct insecure_state *state = FS_DATA;

    gchar *backname = insecure_get_backname (path);
    gchar *full_backname = g_build_path ("/", state->backend_point, backname, NULL);

    int ret = truncate (full_backname, newsize);
    g_free (full_backname);
    g_free (backname);
    return ret;
}

int insecure_utimens (const char *path, const struct timespec tv[2]) {
    insecure_flush_tables ();

    gchar *backname = insecure_get_backname (path);
    gchar *full_backname = g_build_path ("/", FS_DATA->backend_point, backname, NULL);

    int fd = open (full_backname, O_RDONLY);
    if (fd < 0) return -errno;
    int ret = futimens (fd, tv);
    close (fd);

    g_free (backname);
    g_free (full_backname);

    if (ret < 0) return -errno;

    return 0;
}

int insecure_unlink (const char *path) {
    insecure_flush_tables ();

    gchar *backname = insecure_get_backname (path);
    gchar *full_backname = g_build_path ("/", FS_DATA->backend_point, backname, NULL);
    printf ("unlink '%s'\n", path);

    int ret = unlink (full_backname);
    g_free (backname);
    g_free (full_backname);

    sqlite3_stmt *stmt;

    sqlite3_prepare_v2 (FS_DATA->db, "DELETE FROM fit WHERE fname=?", -1, &stmt, NULL);
    sqlite3_bind_text (stmt, 1, path, -1, SQLITE_TRANSIENT);
    sqlite3_step (stmt);
    sqlite3_finalize (stmt);
    if (0 == ret) return 0;

    return -errno;
}

int insecure_rmdir (const char *path) {
    insecure_flush_tables ();

    gchar *backname = insecure_get_backname (path);
    gchar *full_backname = g_build_path ("/", FS_DATA->backend_point, backname, NULL);
    printf ("rmdir '%s'\n", path);

    int ret = rmdir (full_backname);
    g_free (backname);
    g_free (full_backname);

    sqlite3_stmt *stmt;

    sqlite3_prepare_v2 (FS_DATA->db, "DELETE FROM fit WHERE fname=?", -1, &stmt, NULL);
    sqlite3_bind_text (stmt, 1, path, -1, SQLITE_TRANSIENT);
    sqlite3_step (stmt);
    sqlite3_finalize (stmt);
    if (0 == ret) return 0;

    return -errno;
}

int insecure_symlink (const char *path, const char *dest) {
    insecure_flush_tables ();
    printf ("symlink '%s' to '%s'\n", path, dest);

    gchar *full_backname = insecure_insert_name_to_db (dest);
    int ret = symlink (path, full_backname);
    g_free (full_backname);

    return ret;
}

int insecure_readlink (const char *path, char *link, size_t size) {
    insecure_flush_tables ();

    gchar *backname = insecure_get_backname (path);
    gchar *full_backname = g_build_path ("/", FS_DATA->backend_point, backname, NULL);

    ssize_t ret = readlink (full_backname, link, size - 1);
    if (ret < 0) return -errno;

    link[ret] = 0;
    return 0;
}


struct fuse_operations insecure_op = {
    .getattr = insecure_getattr,
    .mknod = insecure_mknod,
    .mkdir = insecure_mkdir,
    .readdir = insecure_readdir,
    .init = insecure_init,
    .destroy = insecure_destroy,
    .open = insecure_open,
    .release = insecure_release,
    .read = insecure_read,
    .write = insecure_write,
    .access = insecure_access,
    .truncate = insecure_truncate,
    .utimens = insecure_utimens,
    .unlink = insecure_unlink,
    .symlink = insecure_symlink,
    .readlink = insecure_readlink,
    .rmdir = insecure_rmdir,
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

    int f_argc = 6;
    char *f_argv[] = {argv[0], "-f", "-s", "-o", "nonempty", state->mount_point};

    res = fuse_main (f_argc, f_argv, &insecure_op, state);
    printf ("fuse_main returned %d\n", res);
}
