/* psa_store_posix.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPSA.
 *
 * wolfPSA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPSA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* glibc exposes O_PATH, which the ancestor walk needs to traverse a directory
 * it may not read, only under _GNU_SOURCE. Must precede every include. */
#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "psa_config.h"

#if !defined(WOLFPSA_CUSTOM_STORE)

#include <psa_store.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <errno.h>
#include <string.h>

#if !defined(_WIN32) && !defined(_MSC_VER)
    #include <sys/stat.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <time.h>
#endif

/* WOLFPSA_STORE_NOT_AVAILABLE / WOLFPSA_STORE_IO_ERROR come from psa_store.h. */
#define WOLFPSA_STORE_MAX_PATH        256

#if defined(_WIN32) || defined(_MSC_VER)
    #define WOLFPSA_MKDIR(path) _mkdir(path)
    #define WOLFPSA_RMDIR(path) _rmdir(path)
#else
    #define WOLFPSA_MKDIR(path) mkdir((path), 0700)
    #define WOLFPSA_RMDIR(path) rmdir(path)
#endif

typedef struct WOLFPSA_FileStoreCtx {
    XFILE file;
    int is_write;
    int has_temp;
    int write_failed;
    char final_name[WOLFPSA_STORE_MAX_PATH];
    char temp_name[WOLFPSA_STORE_MAX_PATH];
} WOLFPSA_FileStoreCtx;

static void wolfPSA_StoreAbortTemp(WOLFPSA_FileStoreCtx* ctx)
{
    if (ctx != NULL && ctx->has_temp) {
        remove(ctx->temp_name);
        ctx->has_temp = 0;
    }
}

static int wolfPSA_StoreCommitTemp(WOLFPSA_FileStoreCtx* ctx)
{
    int ret = 0;

    if (ctx == NULL || ctx->has_temp == 0) {
        return 0;
    }

#if defined(_WIN32) || defined(_MSC_VER)
    if (!MoveFileExA(ctx->temp_name, ctx->final_name,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ret = WOLFPSA_STORE_IO_ERROR;
    }
#else
    if (rename(ctx->temp_name, ctx->final_name) != 0) {
        ret = WOLFPSA_STORE_IO_ERROR;
    }
#endif

    if (ret == 0) {
        ctx->has_temp = 0;
    }

    return ret;
}

#if !defined(_WIN32) && !defined(_MSC_VER)
/* Traversing a directory needs search permission, not read: a 0111 ancestor
 * is a legitimate hardening choice that O_RDONLY would refuse. */
#if defined(O_PATH)
    #define WOLFPSA_O_DIRWALK (O_PATH | O_DIRECTORY | O_CLOEXEC)
#elif defined(O_SEARCH)
    #define WOLFPSA_O_DIRWALK (O_SEARCH | O_DIRECTORY | O_CLOEXEC)
#else
    /* Last resort: this one does need read permission, so a search-only
     * directory in the path is refused. */
    #define WOLFPSA_O_DIRWALK (O_RDONLY | O_DIRECTORY | O_CLOEXEC)
#endif

/* A single path component, so the walk never needs the whole path in memory. */
#define WOLFPSA_STORE_MAX_COMPONENT 256

/* Deeper than any real store path; stops a pathological filesystem from
 * spinning the parent walk. */
#define WOLFPSA_STORE_MAX_DEPTH 256
#endif

/* A path is either fine, refused by the privacy policy, or could not be
 * checked because a syscall failed. The caller fails closed on both of the
 * latter, but only a refusal justifies destroying anything. */
enum {
    WOLFPSA_STORE_PATH_OK = 0,
    WOLFPSA_STORE_PATH_REJECTED,
    WOLFPSA_STORE_PATH_UNKNOWN
};

static int wolfPSA_StoreCheckLeaf(const char* dirPath)
{
#if defined(_WIN32) || defined(_MSC_VER)
    DWORD attrs;

    attrs = GetFileAttributesA(dirPath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return WOLFPSA_STORE_PATH_UNKNOWN;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return WOLFPSA_STORE_PATH_REJECTED;
    }
    return WOLFPSA_STORE_PATH_OK;
#else
    struct stat st;

    if (lstat(dirPath, &st) != 0) {
        return WOLFPSA_STORE_PATH_UNKNOWN;
    }
    if (!S_ISDIR(st.st_mode)) {
        return WOLFPSA_STORE_PATH_REJECTED;
    }
#ifdef S_ISLNK
    if (S_ISLNK(st.st_mode)) {
        return WOLFPSA_STORE_PATH_REJECTED;
    }
#endif
    /* A directory writable by group or other, or owned by neither this euid
     * nor root, lets a local peer rename records out from under the store.
     * Root ownership is accepted, as OpenSSH's safe_path() does. */
    if ((st.st_uid != geteuid() && st.st_uid != 0) ||
        (st.st_mode & 0022) != 0) {
        return WOLFPSA_STORE_PATH_REJECTED;
    }
    return WOLFPSA_STORE_PATH_OK;
#endif
}

#if !defined(_WIN32) && !defined(_MSC_VER)
static int wolfPSA_StoreCheckDirFd(int fd)
{
    struct stat st;
    int sticky;

    if (fstat(fd, &st) != 0) {
        return WOLFPSA_STORE_PATH_UNKNOWN;
    }
    if (!S_ISDIR(st.st_mode)) {
        return WOLFPSA_STORE_PATH_REJECTED;
    }
    if (st.st_uid != geteuid() && st.st_uid != 0) {
        return WOLFPSA_STORE_PATH_REJECTED;
    }
#ifdef S_ISVTX
    sticky = (st.st_mode & S_ISVTX) != 0;
#else
    sticky = 0;
#endif
    /* Unlike the store directory itself, a shared parent such as /tmp is
     * acceptable when sticky: only the owner can rename an entry out of it. */
    if ((st.st_mode & 0022) != 0 && !sticky) {
        return WOLFPSA_STORE_PATH_REJECTED;
    }
    return WOLFPSA_STORE_PATH_OK;
}

/* Walk the path as written, so that every directory holding a component is
 * trusted: whoever can write one can swap that component for a symlink of
 * their own. On success *leafFd is the store directory, left open for the
 * parent walk so the path is not resolved a second time. */
static int wolfPSA_StoreCheckLexical(const char* dirPath, int* leafFd)
{
    char comp[WOLFPSA_STORE_MAX_COMPONENT];
    const char* p = dirPath;
    const char* slash;
    size_t len;
    int fd;
    int next;
    int ret;
    int depth;

    fd = open((dirPath[0] == '/') ? "/" : ".", WOLFPSA_O_DIRWALK);
    if (fd < 0) {
        return WOLFPSA_STORE_PATH_UNKNOWN;
    }

    for (depth = 0; depth < WOLFPSA_STORE_MAX_DEPTH; depth++) {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            *leafFd = fd;
            return WOLFPSA_STORE_PATH_OK;
        }

        slash = strchr(p, '/');
        len = (slash != NULL) ? (size_t)(slash - p) : XSTRLEN(p);
        if (len >= sizeof(comp)) {
            close(fd);
            return WOLFPSA_STORE_PATH_UNKNOWN;
        }
        XMEMCPY(comp, p, len);
        comp[len] = '\0';

        /* "." and ".." are resolved by the kernel and cannot be swapped, so
         * the directory holding them need not be trusted. */
        if (XSTRNCMP(comp, ".", sizeof(comp)) != 0 &&
            XSTRNCMP(comp, "..", sizeof(comp)) != 0) {
            ret = wolfPSA_StoreCheckDirFd(fd);
            if (ret != WOLFPSA_STORE_PATH_OK) {
                close(fd);
                return ret;
            }
        }

        next = openat(fd, comp, WOLFPSA_O_DIRWALK);
        close(fd);
        if (next < 0) {
            return WOLFPSA_STORE_PATH_UNKNOWN;
        }
        fd = next;
        p += len;
    }

    close(fd);
    return WOLFPSA_STORE_PATH_UNKNOWN;
}

/* Whoever can write a real ancestor can rename the store aside, and those
 * ancestors need not appear in the path when a component is a symlink. Takes
 * ownership of fd. */
static int wolfPSA_StoreCheckAncestors(int fd)
{
    struct stat st;
    struct stat parent_st;
    int parent;
    int ret;
    int depth;

    if (fstat(fd, &st) != 0) {
        close(fd);
        return WOLFPSA_STORE_PATH_UNKNOWN;
    }

    for (depth = 0; depth < WOLFPSA_STORE_MAX_DEPTH; depth++) {
        parent = openat(fd, "..", WOLFPSA_O_DIRWALK);
        close(fd);
        if (parent < 0) {
            return WOLFPSA_STORE_PATH_UNKNOWN;
        }
        if (fstat(parent, &parent_st) != 0) {
            close(parent);
            return WOLFPSA_STORE_PATH_UNKNOWN;
        }
        /* The root is its own parent, which is where the walk stops. */
        if (parent_st.st_ino == st.st_ino && parent_st.st_dev == st.st_dev) {
            close(parent);
            return WOLFPSA_STORE_PATH_OK;
        }

        ret = wolfPSA_StoreCheckDirFd(parent);
        if (ret != WOLFPSA_STORE_PATH_OK) {
            close(parent);
            return ret;
        }

        st = parent_st;
        fd = parent;
    }

    close(fd);
    return WOLFPSA_STORE_PATH_UNKNOWN;
}
#endif

static int wolfPSA_StoreCheckPath(const char* dirPath)
{
    int ret = wolfPSA_StoreCheckLeaf(dirPath);
#if !defined(_WIN32) && !defined(_MSC_VER)
    int leafFd = -1;

    if (ret != WOLFPSA_STORE_PATH_OK) {
        return ret;
    }
    ret = wolfPSA_StoreCheckLexical(dirPath, &leafFd);
    if (ret != WOLFPSA_STORE_PATH_OK) {
        return ret;
    }
    ret = wolfPSA_StoreCheckAncestors(leafFd);
#endif
    return ret;
}

static int wolfPSA_StoreValidatePath(const char* dirPath)
{
    return (wolfPSA_StoreCheckPath(dirPath) == WOLFPSA_STORE_PATH_OK)
           ? 0 : WOLFPSA_STORE_IO_ERROR;
}

static int wolfPSA_StoreEnsureDir(const char* dirPath)
{
    int ret;

    if (dirPath == NULL || dirPath[0] == '\0') {
        return WOLFPSA_STORE_IO_ERROR;
    }

    ret = wolfPSA_StoreValidatePath(dirPath);
    if (ret == 0) {
        return 0;
    }

    if (WOLFPSA_MKDIR(dirPath) == 0) {
        ret = wolfPSA_StoreCheckPath(dirPath);
        if (ret == WOLFPSA_STORE_PATH_REJECTED) {
            /* Created here, refused here: do not leave it behind. A check
             * that could not run is not a refusal, so the directory stays. */
            (void)WOLFPSA_RMDIR(dirPath);
        }
        return (ret == WOLFPSA_STORE_PATH_OK) ? 0 : WOLFPSA_STORE_IO_ERROR;
    }

    if (errno == EEXIST) {
        return wolfPSA_StoreValidatePath(dirPath);
    }

    return WOLFPSA_STORE_IO_ERROR;
}

static int wolfPSA_StoreCreateTempFile(WOLFPSA_FileStoreCtx* ctx,
                                       const char* dirPath)
{
    if (ctx == NULL) {
        return WOLFPSA_STORE_IO_ERROR;
    }

#if defined(_WIN32) || defined(_MSC_VER)
    char templateBuf[WOLFPSA_STORE_MAX_PATH];
    int ret;
    int fd;

    ret = XSNPRINTF(templateBuf, sizeof(templateBuf),
                    "%s/psa_tmp_%08lx_%08lx_XXXXXX", dirPath,
                    (unsigned long)_getpid(), (unsigned long)GetTickCount());
    if (ret <= 0 || ret >= (int)sizeof(templateBuf)) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    if (_mktemp_s(templateBuf, sizeof(templateBuf)) != 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    fd = _open(templateBuf, _O_CREAT | _O_EXCL | _O_BINARY | _O_WRONLY,
               _S_IREAD | _S_IWRITE);
    if (fd == -1) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    ctx->file = _fdopen(fd, "wb");
    if (ctx->file == NULL) {
        _close(fd);
        _unlink(templateBuf);
        return WOLFPSA_STORE_IO_ERROR;
    }

    {
        size_t copy_len = XSTRLEN(templateBuf);
        if (copy_len >= sizeof(ctx->temp_name)) {
            copy_len = sizeof(ctx->temp_name) - 1;
        }
        XMEMCPY(ctx->temp_name, templateBuf, copy_len);
        ctx->temp_name[copy_len] = '\0';
    }
    ctx->has_temp = 1;

    return 0;
#else
    char templateBuf[WOLFPSA_STORE_MAX_PATH];
    int fd;
    int ret;

    ret = XSNPRINTF(templateBuf, sizeof(templateBuf),
                    "%s/psa_tmp_%08lx_%08lx_XXXXXX", dirPath,
                    (unsigned long)getpid(), (unsigned long)time(NULL));
    if (ret <= 0 || ret >= (int)sizeof(templateBuf)) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    fd = mkstemp(templateBuf);
    if (fd < 0) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        close(fd);
        unlink(templateBuf);
        return WOLFPSA_STORE_IO_ERROR;
    }

    ctx->file = fdopen(fd, "wb");
    if (ctx->file == NULL) {
        close(fd);
        unlink(templateBuf);
        return WOLFPSA_STORE_IO_ERROR;
    }

    {
        size_t copy_len = XSTRLEN(templateBuf);
        if (copy_len >= sizeof(ctx->temp_name)) {
            copy_len = sizeof(ctx->temp_name) - 1;
        }
        XMEMCPY(ctx->temp_name, templateBuf, copy_len);
        ctx->temp_name[copy_len] = '\0';
    }
    ctx->has_temp = 1;

    return 0;
#endif
}

static int wolfPSA_Store_Name(int type, unsigned long id1, unsigned long id2,
                              char* name, int nameLen)
{
    int ret = 0;
    const char* str = NULL;
    enum wolfpsa_store_name_suffix { WOLFPSA_STORE_SUFFIX_RESERVE = 48 };

    str = XGETENV("WOLFPSA_TOKEN_PATH");

    if (str == NULL) {
#ifdef WOLFPSA_DEFAULT_TOKEN_PATH
        str = WC_STRINGIFY(WOLFPSA_DEFAULT_TOKEN_PATH);
#else
        /* Default to local store path for sandboxed testing. */
        str = "./.store";
#endif
    }

    if (str == NULL) {
        return -1;
    }
    if (nameLen <= WOLFPSA_STORE_SUFFIX_RESERVE) {
        return -1;
    }
    if (XSTRLEN(str) > (size_t)(nameLen - WOLFPSA_STORE_SUFFIX_RESERVE - 1)) {
        return -1;
    }

    switch (type) {
    case WOLFPSA_STORE_KEY:
        ret = XSNPRINTF(name, nameLen, "%s/psa_key_%016lx_%016lx", str,
                        id1, id2);
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

int wolfPSA_Store_Remove(int type, unsigned long id1, unsigned long id2)
{
    int ret;
    const char* str = NULL;
    char name[WOLFPSA_STORE_MAX_PATH] = "\0";

    str = XGETENV("WOLFPSA_NO_STORE");
    if (str != NULL) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }

    ret = wolfPSA_Store_Name(type, id1, id2, name, sizeof(name));
    if (ret > 0 && ret < (int)sizeof(name)) {
        ret = 0;
    }
    else if (ret != 0) {
        ret = -1;
    }

    if (ret == 0) {
        ret = remove(name);
        if (ret != 0 && errno == ENOENT) {
            ret = WOLFPSA_STORE_NOT_AVAILABLE;
        }
    }

    return ret;
}

/* Copy the directory part of a record path into dirPath. */
static int wolfPSA_StoreDirOfName(const char* name, char* dirPath,
                                  size_t dirPathSz)
{
    const char* lastSlash = NULL;
    size_t nameLen = XSTRLEN(name);
    size_t dirLen;
    size_t i;

    for (i = 0; i < nameLen; i++) {
        if (name[i] == '/' || name[i] == '\\') {
            lastSlash = &name[i];
        }
    }

    if (lastSlash == NULL) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    dirLen = (size_t)(lastSlash - name);
    if (dirLen == 0 || dirLen >= dirPathSz) {
        return WOLFPSA_STORE_IO_ERROR;
    }

    XMEMCPY(dirPath, name, dirLen);
    dirPath[dirLen] = '\0';

    return 0;
}

int wolfPSA_Store_OpenSz(int type, unsigned long id1, unsigned long id2, int
                         read,
                         int variableSz, void** store)
{
    int ret = 0;
    const char* str = NULL;
    WOLFPSA_FileStoreCtx* ctx = NULL;
    char name[WOLFPSA_STORE_MAX_PATH] = "\0";

    str = XGETENV("WOLFPSA_NO_STORE");
    if (str != NULL) {
        return WOLFPSA_STORE_NOT_AVAILABLE;
    }

    ret = wolfPSA_Store_Name(type, id1, id2, name, sizeof(name));
    if (ret > 0 && ret < (int)sizeof(name)) {
        ret = 0;
    }
    else if (ret != 0) {
        ret = -1;
    }

    if (ret == 0) {
        ctx = (WOLFPSA_FileStoreCtx*)XMALLOC(sizeof(*ctx), NULL,
                                             DYNAMIC_TYPE_TMP_BUFFER);
        if (ctx == NULL) {
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        char dirPath[WOLFPSA_STORE_MAX_PATH];

        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->file = XBADFILE;
        ctx->is_write = (read == 0);

        {
            size_t finalLen = XSTRLEN(name);
            if (finalLen >= sizeof(ctx->final_name)) {
                ret = WOLFPSA_STORE_IO_ERROR;
            }
            else {
                XMEMCPY(ctx->final_name, name, finalLen + 1);
            }
        }

        if (ret == 0 && read) {
            ctx->file = XFOPEN(name, "rb");
            if (ctx->file == NULL) {
                if (errno == ENOENT) {
                    ret = WOLFPSA_STORE_NOT_AVAILABLE;
                }
                else {
                    ret = WOLFPSA_STORE_IO_ERROR;
                }
            }
            else {
                /* A record is only worth reading back out of a private
                 * directory: a peer that can write the directory can swap the
                 * record for one of its own, which is the substitution the
                 * write path already refuses. Checked after the open, so a
                 * store that does not exist yet still reports "not
                 * available" rather than an I/O error. */
                ret = wolfPSA_StoreDirOfName(name, dirPath, sizeof(dirPath));
                if (ret == 0) {
                    ret = wolfPSA_StoreValidatePath(dirPath);
                }
            }
        }
        else if (ret == 0) {
            ret = wolfPSA_StoreDirOfName(name, dirPath, sizeof(dirPath));
            if (ret == 0) {
                ret = wolfPSA_StoreEnsureDir(dirPath);
            }
            if (ret == 0) {
                ret = wolfPSA_StoreCreateTempFile(ctx, dirPath);
            }
        }
    }

    if (ret == 0 && (ctx->file == NULL || ctx->file == XBADFILE)) {
        ret = WOLFPSA_STORE_IO_ERROR;
    }

    if (ret == 0) {
        *store = ctx;
    }
    else if (ctx != NULL) {
        if (ctx->file != NULL && ctx->file != XBADFILE) {
            XFCLOSE(ctx->file);
        }
        if (ctx->has_temp) {
            wolfPSA_StoreAbortTemp(ctx);
        }
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        ctx = NULL;
    }

    (void)variableSz;
    return ret;
}

int wolfPSA_Store_Open(int type, unsigned long id1, unsigned long id2, int read,
                       void** store)
{
    return wolfPSA_Store_OpenSz(type, id1, id2, read, 0, store);
}

int wolfPSA_Store_Close(void* store)
{
    WOLFPSA_FileStoreCtx* ctx = (WOLFPSA_FileStoreCtx*)store;
    int ret = WOLFPSA_STORE_OK;

    if (ctx != NULL) {
        int commitRet = 0;

        if (ctx->file != XBADFILE && ctx->file != NULL) {
            if (XFCLOSE(ctx->file) != 0) {
                /* Buffered data may have been lost on the way out: mark the
                 * write failed so the commit below aborts instead of
                 * renaming a truncated record over a good one. */
                ctx->write_failed = 1;
                ret = WOLFPSA_STORE_IO_ERROR;
            }
            ctx->file = XBADFILE;
        }

        if (ctx->is_write && ctx->has_temp && ctx->write_failed == 0) {
            commitRet = wolfPSA_StoreCommitTemp(ctx);
            if (commitRet != 0) {
                wolfPSA_StoreAbortTemp(ctx);
                ret = WOLFPSA_STORE_IO_ERROR;
            }
        }
        else if (ctx->has_temp) {
            /* A write handle whose write already failed has nothing
             * committed, and psa_store.h makes this return value the place
             * that is reported. */
            wolfPSA_StoreAbortTemp(ctx);
            if (ctx->is_write && ctx->write_failed) {
                ret = WOLFPSA_STORE_IO_ERROR;
            }
        }

        XMEMSET(ctx, 0, sizeof(*ctx));
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return ret;
}

int wolfPSA_Store_Read(void* store, unsigned char* buffer, int len)
{
    int ret = BUFFER_E;
    WOLFPSA_FileStoreCtx* ctx = (WOLFPSA_FileStoreCtx*)store;

    if (ctx != NULL && ctx->file != XBADFILE && ctx->file != NULL) {
        ret = (int)XFREAD(buffer, 1, len, ctx->file);
    }

    return ret;
}

int wolfPSA_Store_Write(void* store, unsigned char* buffer, int len)
{
    int ret = BUFFER_E;
    WOLFPSA_FileStoreCtx* ctx = (WOLFPSA_FileStoreCtx*)store;

    if (ctx != NULL && ctx->file != XBADFILE && ctx->file != NULL) {
        ret = (int)XFWRITE(buffer, 1, len, ctx->file);
        if (ret == len) {
            if (XFFLUSH(ctx->file) != 0) {
                ctx->write_failed = 1;
                ret = WOLFPSA_STORE_IO_ERROR;
            }
        }
        else {
            ctx->write_failed = 1;
        }
    }

    return ret;
}

#endif /* !WOLFPSA_CUSTOM_STORE */
