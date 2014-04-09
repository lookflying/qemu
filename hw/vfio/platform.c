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
    do { fprintf(stderr, "vfio: %s: " fmt, __func__, ## __VA_ARGS__); } \
        while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define PLATFORM_NUM_REGIONS 10

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


#define VFIO_INT_INTp 4

typedef struct VFIOINTp {
    QLIST_ENTRY(VFIOINTp) next;
    EventNotifier interrupt; /* eventfd triggered on interrupt */
    EventNotifier unmask; /* eventfd for unmask on QEMU bypass */
    qemu_irq qemuirq;
    struct VFIODevice *vdev; /* back pointer to device */
    bool pending; /* interrupt pending */
    bool kvm_accel; /* set when QEMU bypass through KVM enabled */
    uint8_t pin; /* index */
    uint32_t mmap_timeout; /* delay to re-enable mmaps after interrupt */
    QEMUTimer *mmap_timer; /* enable mmaps after periods w/o interrupts */
} VFIOINTp;



typedef struct VFIODevice {
    SysBusDevice sbdev;
    int fd;
    int num_regions;
    int num_irqs;
    int interrupt; /* type of the interrupt, might disappear */
    char *name;
    uint32_t mmap_timeout; /* mmap timeout value in ms */
    VFIORegion regions[PLATFORM_NUM_REGIONS];
    QLIST_ENTRY(VFIODevice) next;
    struct VFIOGroup *group;
    QLIST_HEAD(, VFIOINTp) intp_list;
} VFIODevice;



static void vfio_unmask_intp(VFIODevice *vdev, int index)
{
    struct vfio_irq_set irq_set = {
        .argsz = sizeof(irq_set),
        .flags = VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_UNMASK,
        .index = index,
        .start = 0,
        .count = 1,
    };

    ioctl(vdev->fd, VFIO_DEVICE_SET_IRQS, &irq_set);
}




static void vfio_intp_mmap_enable(void *opaque)
{
    VFIOINTp * intp = (VFIOINTp *)opaque;
    VFIODevice *vdev = intp->vdev;

    if (intp->pending) {
        DPRINTF("IRQ still pending, re-schedule the mmap timer\n");
        timer_mod(intp->mmap_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + intp->mmap_timeout);
        return;
    }

    DPRINTF("IRQ EOI'ed sets mmap again\n");
    VFIORegion *region = &vdev->regions[0];
    memory_region_set_enabled(&region->mmap_mem, true);
}



static void vfio_intp_interrupt(void *opaque)
{
    int ret;
    VFIOINTp *intp = (VFIOINTp *)opaque;
    VFIODevice *vdev = intp->vdev;

    DPRINTF("pin = %d fd = %d\n",
            intp->pin, event_notifier_get_fd(&intp->interrupt));

    ret = event_notifier_test_and_clear(&intp->interrupt);
    if (!ret) {
        DPRINTF("Error when clearing fd=%d\n",
                event_notifier_get_fd(&intp->interrupt));
    }

    intp->pending = true;

    /* TODO: fix this number of regions,
     * currently a single region is handled
     */

    VFIORegion *region = &vdev->regions[0];
    memory_region_set_enabled(&region->mmap_mem, false);

    qemu_set_irq(intp->qemuirq, 1);

    /* schedule the mmap timer which will restote mmap path after EOI*/
    if (intp->mmap_timeout) {
        timer_mod(intp->mmap_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + intp->mmap_timeout);
    }

}



static void vfio_irq_eoi(VFIODevice *vdev)
{

    VFIOINTp *intp;
    bool eoi_done = false;

    QLIST_FOREACH(intp, &vdev->intp_list, next) {
        if (intp->pending) {
            if (eoi_done) {
                DPRINTF("several IRQ pending simultaneously: \
                         this is not a supported case yet\n");
            }
            DPRINTF("EOI IRQ #%d fd=%d\n",
                    intp->pin, event_notifier_get_fd(&intp->interrupt));
            intp->pending = false;
            qemu_set_irq(intp->qemuirq, 0);
            vfio_unmask_intp(vdev, intp->pin);
            eoi_done = true;
        }
    }

    return;

}



#if 0
static void vfio_list_intp(VFIODevice *vdev)
{
    VFIOINTp *intp;
    int i = 0;
    QLIST_FOREACH(intp, &vdev->intp_list, next) {
        DPRINTF("IRQ #%d\n", i);
        DPRINTF("- pin = %d\n", intp->pin);
        DPRINTF("- fd = %d\n", event_notifier_get_fd(&intp->interrupt));
        DPRINTF("- pending = %d\n", (int)intp->pending);
        DPRINTF("- kvm_accel = %d\n", (int)intp->kvm_accel);
        i++;
    }
}
#endif

static int vfio_enable_intp(VFIODevice *vdev, unsigned int index)
{
    struct vfio_irq_set *irq_set; /* irq structure passed to vfio kernel */
    int32_t *pfd; /* pointer to the eventfd */
    int ret, argsz;

    int device = vdev->fd;
    SysBusDevice *sbdev = SYS_BUS_DEVICE(vdev);

    vdev->interrupt = VFIO_INT_INTp;

    /* allocate and populate a new VFIOINTp structure put in a queue list */
    VFIOINTp *intp = g_malloc0(sizeof(*intp));
    intp->vdev = vdev;
    intp->pin = index;
    intp->pending = false;
    intp->mmap_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                    vfio_intp_mmap_enable, intp);
    intp->mmap_timeout = 1100;
    /* TO DO: timeout as parameter */

    /* incr sysbus num_irq and sets sysbus->irqp[n] = &intp->qemuirq
     * only the address of the qemu_irq is set here
     */

    sysbus_init_irq(sbdev, &intp->qemuirq);

    /* content is set in sysbus_connect_irq (currently in machine definition) */

    ret = event_notifier_init(&intp->interrupt, 0);
    if (ret) {
        error_report("vfio: Error: event_notifier_init failed ");
        return ret;
    }

    /* build the irq_set to be passed to the vfio kernel driver */

    argsz = sizeof(*irq_set) + sizeof(*pfd);

    irq_set = g_malloc0(argsz);

    if (!irq_set) {
        DPRINTF("failure while allocating memory for irq\n");
        qemu_log_mask(LOG_GUEST_ERROR,
                 "VFIO platform: failure while allocating memory for irq");
        return -errno;
    }

    irq_set->argsz = argsz;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = index;
    irq_set->start = 0;
    irq_set->count = 1;
    pfd = (int32_t *)&irq_set->data;

    *pfd = event_notifier_get_fd(&intp->interrupt);

    DPRINTF("register fd=%d/irq index=%d to kernel\n", *pfd, index);

    qemu_set_fd_handler(*pfd, vfio_intp_interrupt, NULL, intp);

    /* pass the index/fd binding to the kernel driver so that it
     * triggers this fd on HW IRQ
     */
    ret = ioctl(device, VFIO_DEVICE_SET_IRQS, irq_set);

    g_free(irq_set);

    if (ret) {
        error_report("vfio: Error: Failed to pass Int fd to the driver: %m");
        qemu_set_fd_handler(*pfd, NULL, NULL, vdev);
        close(*pfd); /* TO DO : replace by event_notifier_cleanup */
        return -errno;
    }

    /* store the new intp in qlist */

    QLIST_INSERT_HEAD(&vdev->intp_list, intp, next);

    return 0;

}




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
        error_report("(,0x%"HWADDR_PRIx", 0x%"PRIx64", %d) failed: %m",
                     addr, data, size);
    }

    DPRINTF("(region %d+0x%"HWADDR_PRIx", 0x%"PRIx64", %d)\n",
            region->nr, addr, data, size);

    vfio_irq_eoi(container_of(region, VFIODevice, regions[region->nr]));

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
        error_report("(,0x%"HWADDR_PRIx", %d) failed: %m",
                     addr, size);
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

    DPRINTF("(region %d+0x%"HWADDR_PRIx", %d) = 0x%"PRIx64"\n",
            region->nr, addr, size, data);

    vfio_irq_eoi(container_of(region, VFIODevice, regions[region->nr]));

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

   /* IRQ */

    DPRINTF("Num IRQS: %d\n", dev_info.num_irqs);

    vdev->num_irqs = dev_info.num_irqs;

    for (i = 0; i < dev_info.num_irqs; i++) {

        struct vfio_irq_info irq = { .argsz = sizeof(irq) };

        irq.index = i;

        DPRINTF("Retrieve IRQ info from vfio platform driver ...\n");

        ret = ioctl(vdev->fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);

        if (ret) {
            error_report("vfio: error getting device %s irq info",
                         name);
            error_printf("vfio: error getting device %s irq info",
                         name);
        }

        DPRINTF("- IRQ index %d: count %d, flags=0x%x\n",
                                irq.index,
                                irq.count,
                                irq.flags);

        vfio_enable_intp(vdev, irq.index);

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
    VFIODevice *vdev = DO_UPCAST(VFIODevice, sbdev, sbdev);
    VFIODevice *pvdev;

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

    DPRINTF("%s belongs to VFIO group %d\n", vdev->name, groupid);

    group = vfio_get_group(groupid, NULL);
    if (!group) {
        error_report("vfio: failed to get group %d", groupid);
        return;
    }
    snprintf(path, sizeof(path), "%s", vdev->name);

    QLIST_FOREACH(pvdev, &group->device_list, next) {
        DPRINTF("compare %s versus %s\n", pvdev->name, vdev->name);
        if (strcmp(pvdev->name, vdev->name) == 0) {

            DPRINTF("vfio device %s already is attached to group %d\n",
                    vdev->name, groupid);

            vfio_put_group(group, NULL);
            return;
        }
    }

    DPRINTF("Calling vfio_get_device ...\n");

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
    dc->cannot_instantiate_with_device_add_yet = true;
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
