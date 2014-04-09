/*
 * vfio based device assignment support - platform devices
 *
 * Copyright Linaro Limited, 2014
 *
 * Authors:
 *  Kim Phillips <kim.phillips@linaro.org>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on vfio based PCI device assignment support:
 *  Copyright Red Hat, Inc. 2012
 */

#include <dirent.h>
#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/event_notifier.h"
#include "qemu/queue.h"
#include "qemu/range.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "hw/hw.h"
#include "hw/sysbus.h"

#include "vfio-common.h"

#define DEBUG_VFIO
#ifdef DEBUG_VFIO
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "vfio: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

/* Extra debugging, trap acceleration paths for more logging */
#define VFIO_ALLOW_MMAP 1

#define TYPE_VFIO_PLATFORM "vfio-platform"

typedef struct VFIORegion {
    off_t fd_offset; /* offset of region within device fd */
    int fd; /* device fd, allows us to pass VFIORegion as opaque data */
    MemoryRegion mem; /* slow, read/write access */
    MemoryRegion mmap_mem; /* direct mapped access */
    void *mmap;
    size_t size;
    uint32_t flags; /* VFIO region flags (rd/wr/mmap) */
    uint8_t nr; /* cache the region number for debug */
} VFIORegion;

typedef struct VFIODevice {
    SysBusDevice sbdev;
    int fd;
    int num_regions;
    VFIORegion *regions;
    QLIST_ENTRY(VFIODevice) next;
    struct VFIOGroup *group;
    char *name;
} VFIODevice;

static int vfio_mmap_region(VFIODevice *vdev, VFIORegion *region,
                         MemoryRegion *mem, MemoryRegion *submem,
                         void **map, size_t size, off_t offset,
                         const char *name)
{
    int ret = 0;

    if (VFIO_ALLOW_MMAP && size && region->flags & VFIO_REGION_INFO_FLAG_MMAP) {
        int prot = 0;
        ret = 0;

        if (region->flags & VFIO_REGION_INFO_FLAG_READ) {
            prot |= PROT_READ;
        }

        if (region->flags & VFIO_REGION_INFO_FLAG_WRITE) {
            prot |= PROT_WRITE;
        }

        *map = mmap(NULL, size, prot, MAP_SHARED,
                    region->fd, region->fd_offset + offset);
        if (*map == MAP_FAILED) {
            ret = -errno;
            *map = NULL;
            goto error;
        }

        memory_region_init_ram_ptr(submem, OBJECT(vdev), name, size, *map);
    }

    memory_region_add_subregion(mem, offset, submem);

error:
    return ret;
}

/*
 * IO Port/MMIO - Beware of the endians, VFIO is always little endian
 */
static void vfio_region_write(void *opaque, hwaddr addr,
                              uint64_t data, unsigned size)
{
    VFIORegion *region = opaque;
    union {
        uint8_t byte;
        uint16_t word;
        uint32_t dword;
        uint64_t qword;
    } buf;

    switch (size) {
    case 1:
        buf.byte = data;
        break;
    case 2:
        buf.word = data;
        break;
    case 4:
        buf.dword = data;
        break;
    default:
        hw_error("vfio: unsupported write size, %d bytes\n", size);
        break;
    }

    if (pwrite(region->fd, &buf, size, region->fd_offset + addr) != size) {
        error_report("%s(,0x%"HWADDR_PRIx", 0x%"PRIx64", %d) failed: %m",
                     __func__, addr, data, size);
    }

    DPRINTF("%s(region %d+0x%"HWADDR_PRIx", 0x%"PRIx64", %d)\n",
             __func__, region->nr, addr, data, size);
}

static uint64_t vfio_region_read(void *opaque, hwaddr addr, unsigned size)
{
    VFIORegion *region = opaque;
    union {
        uint8_t byte;
        uint16_t word;
        uint32_t dword;
        uint64_t qword;
    } buf;
    uint64_t data = 0;

    if (pread(region->fd, &buf, size, region->fd_offset + addr) != size) {
        error_report("%s(,0x%"HWADDR_PRIx", %d) failed: %m",
                     __func__, addr, size);
        return (uint64_t)-1;
    }

    switch (size) {
    case 1:
        data = buf.byte;
        break;
    case 2:
        data = buf.word;
        break;
    case 4:
        data = buf.dword;
        break;
    default:
        hw_error("vfio: unsupported read size, %d bytes\n", size);
        break;
    }

    DPRINTF("%s(region %d+0x%"HWADDR_PRIx", %d) = 0x%"PRIx64"\n",
            __func__, region->nr, addr, size, data);

    return data;
}

static const MemoryRegionOps vfio_region_ops = {
    .read = vfio_region_read,
    .write = vfio_region_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void vfio_map_region(VFIODevice *vdev, int nr)
{
    VFIORegion *region = &vdev->regions[nr];
    unsigned size = region->size;
    char name[64];

    snprintf(name, sizeof(name), "VFIO %s region %d", vdev->name, nr);

    /* A "slow" read/write mapping underlies all regions  */
    memory_region_init_io(&region->mem, OBJECT(vdev), &vfio_region_ops,
                          region, name, size);

    strncat(name, " mmap", sizeof(name) - strlen(name) - 1);
    if (vfio_mmap_region(vdev, region, &region->mem,
                         &region->mmap_mem, &region->mmap, size, 0, name)) {
        error_report("%s unsupported. Performance may be slow", name);
    }
}

static int vfio_get_device(VFIOGroup *group, const char *name,
                           struct VFIODevice *vdev)
{
    struct vfio_device_info dev_info = { .argsz = sizeof(dev_info) };
    struct vfio_region_info reg_info = { .argsz = sizeof(reg_info) };
    struct vfio_irq_info irq_info = { .argsz = sizeof(irq_info) };
    int ret, i;

    ret = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, name);
    if (ret < 0) {
        error_report("vfio: error getting device %s from group %d: %m",
                     name, group->groupid);
        error_printf("Verify all devices in group %d are bound to the vfio "
                     "platform driver and are not already in use\n",
                     group->groupid);
        return ret;
    }

    vdev->fd = ret;
    vdev->group = group;
    QLIST_INSERT_HEAD(&group->device_list, vdev, next);

    /* Sanity check device */
    ret = ioctl(vdev->fd, VFIO_DEVICE_GET_INFO, &dev_info);
    if (ret) {
        error_report("vfio: error getting device info: %m");
        goto error;
    }

    DPRINTF("Device %s flags: %u, regions: %u, irqs: %u\n", name,
            dev_info.flags, dev_info.num_regions, dev_info.num_irqs);

    vdev->regions = g_malloc0(sizeof(VFIORegion) * dev_info.num_regions);
    if (!vdev->regions) {
            error_report("vfio: Error allocating space for %d regions",
                         dev_info.num_regions);
            ret = -ENOMEM;
            goto error;
    }

    vdev->num_regions = dev_info.num_regions;

    for (i = 0; i < dev_info.num_regions; i++) {
        reg_info.index = i;

        ret = ioctl(vdev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg_info);
        if (ret) {
            error_report("vfio: Error getting region %d info: %m", i);
            goto error;
        }

        DPRINTF("Device %s region %d:\n", name, i);
        DPRINTF("  size: 0x%lx, offset: 0x%lx, flags: 0x%lx\n",
                (unsigned long)reg_info.size, (unsigned long)reg_info.offset,
                (unsigned long)reg_info.flags);

        vdev->regions[i].flags = reg_info.flags;
        vdev->regions[i].size = reg_info.size;
        vdev->regions[i].fd_offset = reg_info.offset;
        vdev->regions[i].fd = vdev->fd;
        vdev->regions[i].nr = i;
    }

error:
    if (ret) {
        g_free(vdev->regions);
        QLIST_REMOVE(vdev, next);
        vdev->group = NULL;
        close(vdev->fd);
    }
    return ret;
}

static void vfio_platform_realize(DeviceState *dev, Error **errp)
{
    SysBusDevice *sbdev = SYS_BUS_DEVICE(dev);
    VFIODevice *pvdev, *vdev = DO_UPCAST(VFIODevice, sbdev, sbdev);
    VFIOGroup *group;
    char path[PATH_MAX], iommu_group_path[PATH_MAX], *group_name;
    ssize_t len;
    struct stat st;
    int groupid, i, ret;

    /* TODO: pass device name on command line */
    vdev->name = malloc(PATH_MAX);
    strcpy(vdev->name, "fff51000.ethernet");

    /* Check that the host device exists */
    snprintf(path, sizeof(path), "/sys/bus/platform/devices/%s/", vdev->name);
    if (stat(path, &st) < 0) {
        error_report("vfio: error: no such host device: %s", path);
        return;
    }

    strncat(path, "iommu_group", sizeof(path) - strlen(path) - 1);

    len = readlink(path, iommu_group_path, PATH_MAX);
    if (len <= 0) {
        error_report("vfio: error no iommu_group for device");
        return;
    }

    iommu_group_path[len] = 0;
    group_name = basename(iommu_group_path);

    if (sscanf(group_name, "%d", &groupid) != 1) {
        error_report("vfio: error reading %s: %m", path);
        return;
    }

    DPRINTF("%s(%s) group %d\n", __func__, vdev->name, groupid);

    group = vfio_get_group(groupid, NULL);
    if (!group) {
        error_report("vfio: failed to get group %d", groupid);
        return;
    }

    snprintf(path, sizeof(path), "%s", vdev->name);

    QLIST_FOREACH(pvdev, &group->device_list, next) {
        if (strcmp(pvdev->name, vdev->name) == 0) {
            error_report("vfio: error: device %s is already attached", path);
            vfio_put_group(group, NULL);
            return;
        }
    }

    ret = vfio_get_device(group, path, vdev);
    if (ret) {
        error_report("vfio: failed to get device %s", path);
        vfio_put_group(group, NULL);
        return;
    }

    for (i = 0; i < vdev->num_regions; i++) {
        vfio_map_region(vdev, i);
        sysbus_init_mmio(sbdev, &vdev->regions[i].mem);
    }
}

static const VMStateDescription vfio_platform_vmstate = {
    .name = TYPE_VFIO_PLATFORM,
    .unmigratable = 1,
};

static void vfio_platform_dev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = vfio_platform_realize;
    dc->vmsd = &vfio_platform_vmstate;
    dc->desc = "VFIO-based platform device assignment";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo vfio_platform_dev_info = {
    .name = TYPE_VFIO_PLATFORM,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(VFIODevice),
    .class_init = vfio_platform_dev_class_init,
};

static void register_vfio_platform_dev_type(void)
{
    type_register_static(&vfio_platform_dev_info);
}

type_init(register_vfio_platform_dev_type)
