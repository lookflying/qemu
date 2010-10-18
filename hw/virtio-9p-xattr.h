/*
 * Virtio 9p
 *
 * Copyright IBM, Corp. 2010
 *
 * Authors:
 *  Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#ifndef _QEMU_VIRTIO_9P_XATTR_H
#define _QEMU_VIRTIO_9P_XATTR_H

#include <attr/xattr.h>

typedef struct xattr_operations
{
    const char *name;
    ssize_t (*getxattr)(FsContext *ctx, const char *path,
                        const char *name, void *value, size_t size);
    ssize_t (*listxattr)(FsContext *ctx, const char *path,
                         char *name, void *value, size_t size);
    int (*setxattr)(FsContext *ctx, const char *path, const char *name,
                    void *value, size_t size, int flags);
    int (*removexattr)(FsContext *ctx,
                       const char *path, const char *name);
} XattrOperations;


extern XattrOperations mapped_user_xattr;
extern XattrOperations passthrough_user_xattr;

extern XattrOperations *mapped_xattr_ops[];
extern XattrOperations *passthrough_xattr_ops[];
extern XattrOperations *none_xattr_ops[];

extern ssize_t v9fs_get_xattr(FsContext *ctx, const char *path,
                              const char *name, void *value, size_t size);
extern ssize_t v9fs_list_xattr(FsContext *ctx, const char *path,
                               void *value, size_t vsize);
extern int v9fs_set_xattr(FsContext *ctx, const char *path, const char *name,
                          void *value, size_t size, int flags);
extern int v9fs_remove_xattr(FsContext *ctx,
                             const char *path, const char *name);
extern ssize_t pt_listxattr(FsContext *ctx, const char *path,
                            char *name, void *value, size_t size);

static inline ssize_t pt_getxattr(FsContext *ctx, const char *path,
                                  const char *name, void *value, size_t size)
{
    return lgetxattr(rpath(ctx, path), name, value, size);
}

static inline int pt_setxattr(FsContext *ctx, const char *path,
                              const char *name, void *value,
                              size_t size, int flags)
{
    return lsetxattr(rpath(ctx, path), name, value, size, flags);
}

static inline int pt_removexattr(FsContext *ctx,
                                 const char *path, const char *name)
{
    return lremovexattr(rpath(ctx, path), name);
}

#endif
