/*
 * vfio based device assignment support
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Authors:
 *  Alex Williamson <alex.williamson@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Based on qemu-kvm device-assignment:
 *  Adapted for KVM by Qumranet.
 *  Copyright (c) 2007, Neocleus, Alex Novik (alex@neocleus.com)
 *  Copyright (c) 2007, Neocleus, Guy Zana (guy@neocleus.com)
 *  Copyright (C) 2008, Qumranet, Amit Shah (amit.shah@qumranet.com)
 *  Copyright (C) 2008, Red Hat, Amit Shah (amit.shah@redhat.com)
 *  Copyright (C) 2008, IBM, Muli Ben-Yehuda (muli@il.ibm.com)
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
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/pci/pci.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/event_notifier.h"
#include "qemu/queue.h"
#include "qemu/range.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"

#include "vfio-common.h"

#define DEBUG_VFIO
#ifdef DEBUG_VFIO
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, "vfio: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

static QLIST_HEAD(, VFIOContainer)
    container_list = QLIST_HEAD_INITIALIZER(container_list);

QLIST_HEAD(, VFIOGroup)
    group_list = QLIST_HEAD_INITIALIZER(group_list);


struct VFIODevice;

#ifdef CONFIG_KVM
/*
 * We have a single VFIO pseudo device per KVM VM.  Once created it lives
 * for the life of the VM.  Closing the file descriptor only drops our
 * reference to it and the device's reference to kvm.  Therefore once
 * initialized, this file descriptor is only released on QEMU exit and
 * we'll re-use it should another vfio device be attached before then.
 */
static int vfio_kvm_device_fd = -1;
#endif

/*
 * DMA - Mapping and unmapping for the "type1" IOMMU interface used on x86
 */
static int vfio_dma_unmap(VFIOContainer *container,
                          hwaddr iova, ram_addr_t size)
{
    struct vfio_iommu_type1_dma_unmap unmap = {
        .argsz = sizeof(unmap),
        .flags = 0,
        .iova = iova,
        .size = size,
    };

    if (ioctl(container->fd, VFIO_IOMMU_UNMAP_DMA, &unmap)) {
        DPRINTF("VFIO_UNMAP_DMA: %d\n", -errno);
        return -errno;
    }

    return 0;
}

static int vfio_dma_map(VFIOContainer *container, hwaddr iova,
                        ram_addr_t size, void *vaddr, bool readonly)
{
    struct vfio_iommu_type1_dma_map map = {
        .argsz = sizeof(map),
        .flags = VFIO_DMA_MAP_FLAG_READ,
        .vaddr = (__u64)(uintptr_t)vaddr,
        .iova = iova,
        .size = size,
    };

    if (!readonly) {
        map.flags |= VFIO_DMA_MAP_FLAG_WRITE;
    }

    /* add exec flag */
    if (container->iommu_data.has_exec_cap) {
        map.flags |= VFIO_DMA_MAP_FLAG_EXEC;
    }

    /*
     * Try the mapping, if it fails with EBUSY, unmap the region and try
     * again.  This shouldn't be necessary, but we sometimes see it in
     * the the VGA ROM space.
     */
    if (ioctl(container->fd, VFIO_IOMMU_MAP_DMA, &map) == 0 ||
        (errno == EBUSY && vfio_dma_unmap(container, iova, size) == 0 &&
         ioctl(container->fd, VFIO_IOMMU_MAP_DMA, &map) == 0)) {
        return 0;
    }

    DPRINTF("VFIO_MAP_DMA: %d\n", -errno);
    return -errno;
}

static bool vfio_listener_skipped_section(MemoryRegionSection *section)
{
    return !memory_region_is_ram(section->mr) ||
           /*
            * Sizing an enabled 64-bit BAR can cause spurious mappings to
            * addresses in the upper part of the 64-bit address space.  These
            * are never accessed by the CPU and beyond the address width of
            * some IOMMU hardware.  TODO: VFIO should tell us the IOMMU width.
            */
           section->offset_within_address_space & (1ULL << 63);
}

static void vfio_listener_region_add(MemoryListener *listener,
                                     MemoryRegionSection *section)
{
    VFIOContainer *container = container_of(listener, VFIOContainer,
                                            iommu_data.type1.listener);
    hwaddr iova, end;
    void *vaddr;
    int ret;

    assert(!memory_region_is_iommu(section->mr));

    if (vfio_listener_skipped_section(section)) {
        DPRINTF("SKIPPING region_add %"HWADDR_PRIx" - %"PRIx64"\n",
                section->offset_within_address_space,
                section->offset_within_address_space +
                int128_get64(int128_sub(section->size, int128_one())));
        return;
    }

    if (unlikely((section->offset_within_address_space & ~TARGET_PAGE_MASK) !=
                 (section->offset_within_region & ~TARGET_PAGE_MASK))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    iova = TARGET_PAGE_ALIGN(section->offset_within_address_space);
    end = (section->offset_within_address_space + int128_get64(section->size)) &
          TARGET_PAGE_MASK;

    if (iova >= end) {
        return;
    }

    vaddr = memory_region_get_ram_ptr(section->mr) +
            section->offset_within_region +
            (iova - section->offset_within_address_space);

    DPRINTF("region_add %"HWADDR_PRIx" - %"HWADDR_PRIx" [%p]\n",
            iova, end - 1, vaddr);

    memory_region_ref(section->mr);
    ret = vfio_dma_map(container, iova, end - iova, vaddr, section->readonly);
    if (ret) {
        error_report("vfio_dma_map(%p, 0x%"HWADDR_PRIx", "
                     "0x%"HWADDR_PRIx", %p) = %d (%m)",
                     container, iova, end - iova, vaddr, ret);

        /*
         * On the initfn path, store the first error in the container so we
         * can gracefully fail.  Runtime, there's not much we can do other
         * than throw a hardware error.
         */
        if (!container->iommu_data.type1.initialized) {
            if (!container->iommu_data.type1.error) {
                container->iommu_data.type1.error = ret;
            }
        } else {
            hw_error("vfio: DMA mapping failed, unable to continue");
        }
    }
}

static void vfio_listener_region_del(MemoryListener *listener,
                                     MemoryRegionSection *section)
{
    VFIOContainer *container = container_of(listener, VFIOContainer,
                                            iommu_data.type1.listener);
    hwaddr iova, end;
    int ret;

    if (vfio_listener_skipped_section(section)) {
        DPRINTF("SKIPPING region_del %"HWADDR_PRIx" - %"PRIx64"\n",
                section->offset_within_address_space,
                section->offset_within_address_space +
                int128_get64(int128_sub(section->size, int128_one())));
        return;
    }

    if (unlikely((section->offset_within_address_space & ~TARGET_PAGE_MASK) !=
                 (section->offset_within_region & ~TARGET_PAGE_MASK))) {
        error_report("%s received unaligned region", __func__);
        return;
    }

    iova = TARGET_PAGE_ALIGN(section->offset_within_address_space);
    end = (section->offset_within_address_space + int128_get64(section->size)) &
          TARGET_PAGE_MASK;

    if (iova >= end) {
        return;
    }

    DPRINTF("region_del %"HWADDR_PRIx" - %"HWADDR_PRIx"\n",
            iova, end - 1);

    ret = vfio_dma_unmap(container, iova, end - iova);
    memory_region_unref(section->mr);
    if (ret) {
        error_report("vfio_dma_unmap(%p, 0x%"HWADDR_PRIx", "
                     "0x%"HWADDR_PRIx") = %d (%m)",
                     container, iova, end - iova, ret);
    }
}

static MemoryListener vfio_memory_listener = {
    .region_add = vfio_listener_region_add,
    .region_del = vfio_listener_region_del,
};

static void vfio_listener_release(VFIOContainer *container)
{
    memory_listener_unregister(&container->iommu_data.type1.listener);
}

static void vfio_kvm_device_add_group(VFIOGroup *group)
{
#ifdef CONFIG_KVM
    struct kvm_device_attr attr = {
        .group = KVM_DEV_VFIO_GROUP,
        .attr = KVM_DEV_VFIO_GROUP_ADD,
        .addr = (uint64_t)(unsigned long)&group->fd,
    };

    if (!kvm_enabled()) {
        return;
    }

    if (vfio_kvm_device_fd < 0) {
        struct kvm_create_device cd = {
            .type = KVM_DEV_TYPE_VFIO,
        };

        if (kvm_vm_ioctl(kvm_state, KVM_CREATE_DEVICE, &cd)) {
            DPRINTF("KVM_CREATE_DEVICE: %m\n");
            return;
        }

        vfio_kvm_device_fd = cd.fd;
    }

    if (ioctl(vfio_kvm_device_fd, KVM_SET_DEVICE_ATTR, &attr)) {
        error_report("Failed to add group %d to KVM VFIO device: %m",
                     group->groupid);
    }
#endif
}

static void vfio_kvm_device_del_group(VFIOGroup *group)
{
#ifdef CONFIG_KVM
    struct kvm_device_attr attr = {
        .group = KVM_DEV_VFIO_GROUP,
        .attr = KVM_DEV_VFIO_GROUP_DEL,
        .addr = (uint64_t)(unsigned long)&group->fd,
    };

    if (vfio_kvm_device_fd < 0) {
        return;
    }

    if (ioctl(vfio_kvm_device_fd, KVM_SET_DEVICE_ATTR, &attr)) {
        error_report("Failed to remove group %d from KVM VFIO device: %m",
                     group->groupid);
    }
#endif
}

static int vfio_connect_container(VFIOGroup *group)
{
    VFIOContainer *container;
    int ret, fd;

    if (group->container) {
        return 0;
    }

    QLIST_FOREACH(container, &container_list, next) {
        if (!ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &container->fd)) {
            group->container = container;
            QLIST_INSERT_HEAD(&container->group_list, group, container_next);
            return 0;
        }
    }

    fd = qemu_open("/dev/vfio/vfio", O_RDWR);
    if (fd < 0) {
        error_report("vfio: failed to open /dev/vfio/vfio: %m");
        return -errno;
    }

    ret = ioctl(fd, VFIO_GET_API_VERSION);
    if (ret != VFIO_API_VERSION) {
        error_report("vfio: supported vfio version: %d, "
                     "reported version: %d", VFIO_API_VERSION, ret);
        close(fd);
        return -EINVAL;
    }

    container = g_malloc0(sizeof(*container));
    container->fd = fd;

    if (ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
        ret = ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &fd);
        if (ret) {
            error_report("vfio: failed to set group container: %m");
            g_free(container);
            close(fd);
            return -errno;
        }

        ret = ioctl(fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
        if (ret) {
            error_report("vfio: failed to set iommu for container: %m");
            g_free(container);
            close(fd);
            return -errno;
        }

        if (ioctl(fd, VFIO_CHECK_EXTENSION, VFIO_IOMMU_PROT_EXEC)) {
            container->iommu_data.has_exec_cap = true;
        }

        container->iommu_data.type1.listener = vfio_memory_listener;
        container->iommu_data.release = vfio_listener_release;

        memory_listener_register(&container->iommu_data.type1.listener,
                                 &address_space_memory);

        if (container->iommu_data.type1.error) {
            ret = container->iommu_data.type1.error;
            vfio_listener_release(container);
            g_free(container);
            close(fd);
            error_report("vfio: memory listener initialization failed for container");
            return ret;
        }

        container->iommu_data.type1.initialized = true;

    } else {
        error_report("vfio: No available IOMMU models");
        g_free(container);
        close(fd);
        return -EINVAL;
    }

    QLIST_INIT(&container->group_list);
    QLIST_INSERT_HEAD(&container_list, container, next);

    group->container = container;
    QLIST_INSERT_HEAD(&container->group_list, group, container_next);

    return 0;
}

static void vfio_disconnect_container(VFIOGroup *group)
{
    VFIOContainer *container = group->container;

    if (ioctl(group->fd, VFIO_GROUP_UNSET_CONTAINER, &container->fd)) {
        error_report("vfio: error disconnecting group %d from container",
                     group->groupid);
    }

    QLIST_REMOVE(group, container_next);
    group->container = NULL;

    if (QLIST_EMPTY(&container->group_list)) {
        if (container->iommu_data.release) {
            container->iommu_data.release(container);
        }
        QLIST_REMOVE(container, next);
        DPRINTF("vfio_disconnect_container: close container->fd\n");
        close(container->fd);
        g_free(container);
    }
}

VFIOGroup *vfio_get_group(int groupid, QEMUResetHandler *reset_handler)
{
    VFIOGroup *group;
    char path[32];
    struct vfio_group_status status = { .argsz = sizeof(status) };

    QLIST_FOREACH(group, &group_list, next) {
        if (group->groupid == groupid) {
            return group;
        }
    }

    group = g_malloc0(sizeof(*group));

    snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
    group->fd = qemu_open(path, O_RDWR);
    if (group->fd < 0) {
        error_report("vfio: error opening %s: %m", path);
        g_free(group);
        return NULL;
    }

    if (ioctl(group->fd, VFIO_GROUP_GET_STATUS, &status)) {
        error_report("vfio: error getting group status: %m");
        close(group->fd);
        g_free(group);
        return NULL;
    }

    if (!(status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        error_report("vfio: error, group %d is not viable, please ensure "
                     "all devices within the iommu_group are bound to their "
                     "vfio bus driver.", groupid);
        close(group->fd);
        g_free(group);
        return NULL;
    }

    group->groupid = groupid;
    QLIST_INIT(&group->device_list);

    if (vfio_connect_container(group)) {
        error_report("vfio: failed to setup container for group %d", groupid);
        close(group->fd);
        g_free(group);
        return NULL;
    }

    if (QLIST_EMPTY(&group_list) && reset_handler) {
        qemu_register_reset(reset_handler, NULL);
    }

    QLIST_INSERT_HEAD(&group_list, group, next);

    vfio_kvm_device_add_group(group);

    return group;
}

void vfio_put_group(VFIOGroup *group, QEMUResetHandler *reset_handler)
{
    if (!QLIST_EMPTY(&group->device_list)) {
        return;
    }

    vfio_kvm_device_del_group(group);
    vfio_disconnect_container(group);
    QLIST_REMOVE(group, next);
    DPRINTF("vfio_put_group: close group->fd\n");
    close(group->fd);
    g_free(group);

    if (QLIST_EMPTY(&group_list) && reset_handler) {
        qemu_unregister_reset(reset_handler, NULL);
    }
}
