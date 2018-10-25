/*
 * Copyright (c) 2006, 2007 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/hugetlb.h>
#include <linux/atomic.h>
//#include <linux/spinlock.h>

#define DRV_NAME	"nv_mem"
#define DRV_VERSION	"1.1"
#define DRV_RELDATE	__DATE__

#define peer_err(FMT, ARGS...)  printk(KERN_ERR   DRV_NAME " %s:%d " FMT, __FUNCTION__, __LINE__, ## ARGS)

static int enable_info = 0;
#define peer_info(FMT, ARGS...)                                         \
        do {                                                            \
                if (enable_info)                                        \
                        printk(KERN_INFO  DRV_NAME " %s:%d " FMT, __FUNCTION__, __LINE__, ## ARGS); \
        } while(0)

static int enable_dbg = 0;
#define peer_dbg(FMT, ARGS...)                                          \
        do {                                                            \
                if (enable_dbg && printk_ratelimit())                   \
                        printk(KERN_DEBUG DRV_NAME " %s:%d " FMT, __FUNCTION__, __LINE__, ## ARGS); \
        } while(0)

#define MAX_SG_DUMP 0

MODULE_AUTHOR("Yishai Hadas");
MODULE_DESCRIPTION("NVIDIA GPU memory plug-in");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

module_param(enable_dbg, int, 0000);
MODULE_PARM_DESC(enable_dbg, "enable debug tracing");
module_param(enable_info, int, 0000);
MODULE_PARM_DESC(enable_info, "enable info tracing");

#include <rdma/peer_mem.h>

#include <nv-p2p.h>

#ifndef NVIDIA_P2P_MAJOR_VERSION_MASK
#define NVIDIA_P2P_MAJOR_VERSION_MASK   0xffff0000
#endif
#ifndef NVIDIA_P2P_MINOR_VERSION_MASK
#define NVIDIA_P2P_MINOR_VERSION_MASK   0x0000ffff
#endif

#ifndef NVIDIA_P2P_MAJOR_VERSION
#define NVIDIA_P2P_MAJOR_VERSION(v) \
    (((v) & NVIDIA_P2P_MAJOR_VERSION_MASK) >> 16)
#endif

#ifndef NVIDIA_P2P_MINOR_VERSION
#define NVIDIA_P2P_MINOR_VERSION(v) \
    (((v) & NVIDIA_P2P_MINOR_VERSION_MASK))
#endif

#ifndef NVIDIA_P2P_MAJOR_VERSION_MATCHES
#define NVIDIA_P2P_MAJOR_VERSION_MATCHES(p, v) \
    (NVIDIA_P2P_MAJOR_VERSION((p)->version) == NVIDIA_P2P_MAJOR_VERSION(v))
#endif

#ifndef NVIDIA_P2P_VERSION_COMPATIBLE
#define NVIDIA_P2P_VERSION_COMPATIBLE(p, v)             \
    (NVIDIA_P2P_MAJOR_VERSION_MATCHES(p, v) &&          \
    (NVIDIA_P2P_MINOR_VERSION((p)->version) >= NVIDIA_P2P_MINOR_VERSION(v)))
#endif

#ifndef NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE
#define NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(p) \
    NVIDIA_P2P_VERSION_COMPATIBLE(p, NVIDIA_P2P_PAGE_TABLE_VERSION)
#endif

/* 
 * Note: before major version 2, struct dma_mapping had no version field,
 *       so it is not possible to check version compatibility. In this case
 *       let us just avoid dma mappings altogether.
 */
#if defined(NVIDIA_P2P_DMA_MAPPING_VERSION) && \
    (NVIDIA_P2P_MAJOR_VERSION(NVIDIA_P2P_DMA_MAPPING_VERSION) >= 2)
#warning "enabling support for nvidia_p2p_dma_map_pages"
#define NV_DMA_MAPPING 1
#else
#define NV_DMA_MAPPING 0
#endif

#define _DEBUG_ONLY_ 1

/*
 * run-time binding to NV module symbols
 */

static typeof(nvidia_p2p_get_pages) *nv_get_pages;
static typeof(nvidia_p2p_put_pages) *nv_put_pages;
static typeof(nvidia_p2p_free_page_table) *nv_free_page_table;
#if NV_DMA_MAPPING
static typeof(nvidia_p2p_dma_map_pages) *nv_dma_map_pages;
static typeof(nvidia_p2p_dma_unmap_pages) *nv_dma_unmap_pages;
static typeof(nvidia_p2p_free_dma_mapping) *nv_free_dma_mapping;
#endif

static int load_nv_symbols(void)
{
        int retcode = 0;        
#define GET_NV_SYMBOL(FUNPTR, SYMNAME)                                  \
        FUNPTR = symbol_get(SYMNAME);                                   \
        if (!FUNPTR) {                                                  \
                peer_err("can't get symbol for " #SYMNAME "\n");        \
                retcode = -EINVAL;                                      \
        } else {                                                        \
                peer_info(#SYMNAME "=%px\n", FUNPTR);                 \
        }

        do {
                GET_NV_SYMBOL(nv_get_pages,       nvidia_p2p_get_pages);
                GET_NV_SYMBOL(nv_put_pages,       nvidia_p2p_put_pages);
                GET_NV_SYMBOL(nv_free_page_table, nvidia_p2p_free_page_table);
#if NV_DMA_MAPPING
                // TODO: even if compiled with newer NV API, be resilient to older 
                //       NV drivers, e.g. by checking symbol_get of nv_dma_map_pages
                GET_NV_SYMBOL(nv_dma_map_pages,   nvidia_p2p_dma_map_pages);
                GET_NV_SYMBOL(nv_dma_unmap_pages, nvidia_p2p_dma_unmap_pages);
                GET_NV_SYMBOL(nv_free_dma_mapping, nvidia_p2p_free_dma_mapping);
#endif
        } while(0);
        if (retcode) {
                if (nv_get_pages)       symbol_put(nvidia_p2p_get_pages);
                if (nv_put_pages)       symbol_put(nvidia_p2p_put_pages);
                if (nv_free_page_table) symbol_put(nvidia_p2p_free_page_table);
#if NV_DMA_MAPPING
                if (nv_dma_map_pages)   symbol_put(nvidia_p2p_dma_map_pages);
                if (nv_dma_unmap_pages) symbol_put(nvidia_p2p_dma_unmap_pages);
                if (nv_free_dma_mapping)symbol_put(nvidia_p2p_free_dma_mapping);
#endif
                return retcode;
        }
        return 0;
}

static void unload_nv_symbols(void)
{
        if (nv_get_pages)       symbol_put(nvidia_p2p_get_pages);
        if (nv_put_pages)       symbol_put(nvidia_p2p_put_pages);
        if (nv_free_page_table) symbol_put(nvidia_p2p_free_page_table);
#if NV_DMA_MAPPING
        if (nv_dma_map_pages)   symbol_put(nvidia_p2p_dma_map_pages);
        if (nv_dma_unmap_pages) symbol_put(nvidia_p2p_dma_unmap_pages);
        if (nv_free_dma_mapping)symbol_put(nvidia_p2p_free_dma_mapping);
#endif
}


#define GPU_PAGE_SHIFT   16
#define GPU_PAGE_SIZE    ((u64)1 << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)


invalidate_peer_memory mem_invalidate_callback;
static void *reg_handle;

struct nv_mem_context {
	uint64_t guard0;
	struct nvidia_p2p_page_table *page_table;
#if NV_DMA_MAPPING
        struct nvidia_p2p_dma_mapping *dma_mapping;
#endif
	void *core_context;
	u64 page_virt_start;
	u64 page_virt_end;
	size_t mapped_size;
	unsigned long npages;
	unsigned long page_size;
	int is_callback;
	int sg_allocated;
	struct list_head node;
	uint64_t guard1;
};

struct nv_ctx_list {
	struct list_head head;
	spinlock_t lock;
} ctx_list;

static int __ctxlist_is_tracked(struct nv_mem_context *ctx)
{
	int rc = 0;
	struct list_head *cur = NULL;
	
	list_for_each(cur, &ctx_list.head) {
		struct nv_mem_context *cur_ctx = list_entry(cur, struct nv_mem_context, node);
		if (cur_ctx == ctx) {
			rc = 1;
			break;
		}
	}
	return rc;
}

static int ctxlist_is_tracked(struct nv_mem_context *ctx)
{
	int rc = 0;
	unsigned long flags;
	spin_lock_irqsave(&ctx_list.lock, flags);
	rc = __ctxlist_is_tracked(ctx);
	spin_unlock_irqrestore(&ctx_list.lock, flags);
	return rc;
}

static int __ctxlist_add(struct nv_mem_context *ctx)
{
	int rc = 0;
	peer_dbg("ctx:%px\n", ctx);	
	if (!ctx) {
		peer_err("invalid NULL ctx\n");
		rc = EINVAL;
		goto out;
	}
	if (__ctxlist_is_tracked(ctx)) {
		peer_err("ouch, ignoring dup entry for ctx=%px, will not add new instance!!!\n", ctx);
		rc = EAGAIN;
		goto out;
	}
	list_add_tail(&ctx->node, &ctx_list.head);
 out:
	return rc;
}

static int ctxlist_add(struct nv_mem_context *ctx)
{
	int rc = 0;
	unsigned long flags;
	spin_lock_irqsave(&ctx_list.lock, flags);
	rc = __ctxlist_add(ctx);
	spin_unlock_irqrestore(&ctx_list.lock, flags);
	return rc;
}

static int __ctxlist_del(struct nv_mem_context *ctx)
{
	int rc = 0;
	peer_dbg("ctx:%px\n", ctx);
	if (!__ctxlist_is_tracked(ctx)) {		
		peer_err("ouch, ctx=%px is not tracked, while trying to remove from list, nothing to do\n", ctx);
		rc = EINVAL;
		goto out;
	}
	list_del(&ctx->node);
 out:
	return rc;
}

static int ctxlist_del(struct nv_mem_context *ctx)
{
	int rc = 0;
	unsigned long flags;
	spin_lock_irqsave(&ctx_list.lock, flags);
	rc = __ctxlist_del(ctx);
	spin_unlock_irqrestore(&ctx_list.lock, flags);
	return rc;
}

static int ctxlist_is_empty(void)
{
	int rc = 0;
	unsigned long flags;
	spin_lock_irqsave(&ctx_list.lock, flags);
	if (list_empty(&ctx_list.head)) {
		rc = 1;
	}
	spin_unlock_irqrestore(&ctx_list.lock, flags);
	return rc;
}

static void ctxlist_init(void)
{
	INIT_LIST_HEAD(&ctx_list.head);
	spin_lock_init(&ctx_list.lock);
}

static void nv_get_p2p_free_callback(void *data)
{
	int ret = 0;
	struct nv_mem_context *nv_mem_context = (struct nv_mem_context *)data;
	struct nvidia_p2p_page_table *page_table = NULL;
#if NV_DMA_MAPPING
	struct nvidia_p2p_dma_mapping *dma_mapping = NULL;
#endif
	unsigned long flags;
	
	__module_get(THIS_MODULE);
	spin_lock_irqsave(&ctx_list.lock, flags);

	if (!nv_mem_context) {
		peer_err("invalid nv_mem_context\n");
		goto out;
	}

	if (!__ctxlist_is_tracked(nv_mem_context)) {
		peer_err("error, context %px not tracked, ignoring it\n", nv_mem_context);
		goto out;
	}

	if (!nv_mem_context->page_table) {
		peer_err("invalid page_table\n");
		goto out;
	}

	/* Save page_table locally to prevent it being freed as part of nv_mem_release
	    in case it's called internally by that callback.
	*/
	page_table = nv_mem_context->page_table;
#if NV_DMA_MAPPING
	dma_mapping = nv_mem_context->dma_mapping;
#endif

	/* For now don't set nv_mem_context->page_table to NULL.
	 * rdma core code will always call nv_mem_put_pages() and nv_dma_unmap(),
	 * which do partial clean-up if under invalidation callback, thanks to 
	 * nv_mem_context->is_callback==1
	 */
	WRITE_ONCE(nv_mem_context->is_callback, 1);

	peer_err("nv_mem_context:%px page_table:%px dma_mapping:%px VA:%llx-%llx npages:%lu\n",
		 nv_mem_context, page_table, dma_mapping, nv_mem_context->page_virt_start, nv_mem_context->page_virt_end, nv_mem_context->npages);

	// holding ctx_list lock
	(*mem_invalidate_callback) (reg_handle, (uint64_t)nv_mem_context->core_context);

#if NV_DMA_MAPPING
	if (!dma_mapping) {
		peer_err("invalid dma_mapping\n");
	} else {
		ret = nv_free_dma_mapping(dma_mapping);
		if (ret)
			peer_err("nv_get_p2p_free_callback -- error %d while calling nvidia_p2p_free_page_table()\n", ret);
		nv_mem_context->dma_mapping = NULL;
	}
#endif
	if (!page_table) {
		peer_err("invalid page_table\n");
	} else {
		ret = nv_free_page_table(page_table);
		if (ret)
			peer_err("nv_get_p2p_free_callback -- error %d while calling nvidia_p2p_free_page_table()\n", ret);
		nv_mem_context->page_table = NULL;
	}
out:
	spin_unlock_irqrestore(&ctx_list.lock, flags);	
	module_put(THIS_MODULE);
	return;

}

/* At that function we don't call IB core - no ticket exists */
static void nv_mem_dummy_callback(void *data)
{
	struct nv_mem_context *nv_mem_context = (struct nv_mem_context *)data;
	int ret = 0;

	__module_get(THIS_MODULE);


	peer_err("nv_mem_context:%px page_table:%px dma_mapping:%px VA:%llx-%llx npages:%lu\n",
		 nv_mem_context, nv_mem_context->page_table, nv_mem_context->dma_mapping, nv_mem_context->page_virt_start, nv_mem_context->page_virt_end, nv_mem_context->npages);

	ret = nv_free_page_table(nv_mem_context->page_table);
	if (ret)
		peer_err("nv_mem_dummy_callback --  error %d while calling nvidia_p2p_free_page_table()\n", ret);

	module_put(THIS_MODULE);
	return;
}

/* acquire return code: 1 mine, 0 - not mine */
static int nv_mem_acquire(unsigned long addr, size_t size, void *peer_mem_private_data,
					char *peer_mem_name, void **client_context)
{

	int ret = 0;
	struct nv_mem_context *nv_mem_context;

	nv_mem_context = kzalloc(sizeof *nv_mem_context, GFP_KERNEL);
	if (!nv_mem_context)
		/* Error case handled as not mine */
		return 0;

	nv_mem_context->page_virt_start = addr & GPU_PAGE_MASK;
	nv_mem_context->page_virt_end   = (addr + size + GPU_PAGE_SIZE - 1) & GPU_PAGE_MASK;
	nv_mem_context->mapped_size  = nv_mem_context->page_virt_end - nv_mem_context->page_virt_start;

        //peer_dbg("addr=%lx size=%zu page_virt_start=%llx mapped_size=%zu\n", 
        //          addr, size, nv_mem_context->page_virt_start, nv_mem_context->mapped_size);

	ret = nv_get_pages(0, 0, nv_mem_context->page_virt_start, nv_mem_context->mapped_size,
			&nv_mem_context->page_table, nv_mem_dummy_callback, nv_mem_context);

	if (ret < 0) {
		//peer_dbg("nv_mem_acquire -- nvidia_p2p_get_pages error %d for addr=%lx\n", ret, addr);
		goto err;
        }

        if (!NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(nv_mem_context->page_table)) {
                peer_err("error, incompatible page table version 0x%08x\n", nv_mem_context->page_table->version);
                nv_put_pages(0, 0, nv_mem_context->page_virt_start, nv_mem_context->page_table);
                goto err;
        }

	ret = nv_put_pages(0, 0, nv_mem_context->page_virt_start,
                           nv_mem_context->page_table);
	if (ret < 0) {
		/* Not expected, however in case callback was called on that buffer just before
		    put pages we'll expect to fail gracefully (confirmed by NVIDIA) and return an error.
		*/
		peer_err("nv_mem_acquire -- error %d while calling nvidia_p2p_put_pages()\n", ret);
		goto err;
	}
        nv_mem_context->page_table = NULL;

	/* 1 means mine */
	*client_context = nv_mem_context;

	if (ctxlist_add(nv_mem_context)) {
		peer_err("error, failing acquire for dup context %px\n", nv_mem_context);
		goto err;
	}

	peer_dbg("nv_mem_context:%px page_table:%px dma_mapping:%px is_callback:%d\n", nv_mem_context, nv_mem_context->page_table, nv_mem_context->dma_mapping, READ_ONCE(nv_mem_context->is_callback));
	__module_get(THIS_MODULE);
	return 1;

err:
	kfree(nv_mem_context);

	/* Error case handled as not mine */
	return 0;
}

#define dma_to_pci_dev(n) container_of(n, struct pci_dev, dev)

static int nv_dma_map(struct sg_table *sg_head, void *context,
			      struct device *dma_device, int dmasync,
			      int *nmap)
{
	int i, ret;
	struct scatterlist *sg;
	struct nv_mem_context *nv_mem_context =
		(struct nv_mem_context *) context;
	struct nvidia_p2p_page_table *page_table;
	struct pci_dev *pci_device = dma_to_pci_dev(dma_device);
	unsigned long flags;

	spin_lock_irqsave(&ctx_list.lock, flags);
	if (!__ctxlist_is_tracked(nv_mem_context)) {
		peer_err("error, invalid ctx %px\n", nv_mem_context);
		ret = -EINVAL;
		goto out;
	}

	page_table = nv_mem_context->page_table;

	if (!page_table) {
		peer_err("error, invalid p2p page table\n");
		ret = -EINVAL;
		goto out;
	}

	if (page_table->page_size != NVIDIA_P2P_PAGE_SIZE_64KB) {
		peer_err("error, assumption of 64KB pages failed size_id=%u\n",
			 page_table->page_size);
		ret = -EINVAL;
		goto out;
	}

	if (nv_mem_context->sg_allocated) {
		peer_err("error, sg allocated already\n");
		ret = -EINVAL;
		goto out;
	}

	if (!pci_device) {
		peer_err("invalid pci_device\n");
		ret = -EINVAL;
		goto out;
	}

	BUG_ON(nv_mem_context->is_callback);

#if NV_DMA_MAPPING
	{
		struct nvidia_p2p_dma_mapping *dma_mapping;

		ret = nv_dma_map_pages(pci_device, page_table, &dma_mapping);
		if (ret) {
			peer_err("error %d in nvidia_p2p_dma_map_pages\n",
				 ret);
			goto out;
		}

		if (!NVIDIA_P2P_DMA_MAPPING_VERSION_COMPATIBLE(dma_mapping)) {
			peer_err("error, incompatible dma mapping version 0x%08x\n", dma_mapping->version);
			nv_dma_unmap_pages(pci_device, page_table, dma_mapping);
			ret = -EINVAL;
			goto out;
		}
		nv_mem_context->npages = dma_mapping->entries;

		ret = sg_alloc_table(sg_head, dma_mapping->entries, GFP_KERNEL);
		if (ret) {
			nv_dma_unmap_pages(pci_device, page_table, dma_mapping);
			ret = ret;
			goto out;
		}
		nv_mem_context->dma_mapping = dma_mapping;

		nv_mem_context->sg_allocated = 1;
		for_each_sg(sg_head->sgl, sg, dma_mapping->entries, i) {
			sg_set_page(sg, NULL, GPU_PAGE_SIZE, 0);
			sg->dma_address = dma_mapping->dma_addresses[i];
			sg->dma_length = GPU_PAGE_SIZE;
			if (i<MAX_SG_DUMP) 
				peer_dbg("sg[%d] 0x%016llx %u %s\n", 
					  i, sg->dma_address, sg->dma_length, (i==(MAX_SG_DUMP-1))?"and counting...":"");
		}
	}
#else
	nv_mem_context->npages = PAGE_ALIGN(nv_mem_context->mapped_size) >>
						GPU_PAGE_SHIFT;

	if (nv_mem_context->page_table->entries != nv_mem_context->npages) {
		peer_err("error, unexpected number of page table entries got=%u, expected=%lu, leaking kernel resources\n",
			 nv_mem_context->page_table->entries,
			 nv_mem_context->npages);
		ret = -EINVAL;
		goto out;
	}

	ret = sg_alloc_table(sg_head, nv_mem_context->npages, GFP_KERNEL);
	if (ret) {
		// leaking kernel resources
		goto out;
	}

	nv_mem_context->sg_allocated = 1;
	for_each_sg(sg_head->sgl, sg, nv_mem_context->npages, i) {
		sg_set_page(sg, NULL, nv_mem_context->page_size, 0);
		sg->dma_address = page_table->pages[i]->physical_address;
		sg->dma_length = nv_mem_context->page_size;
		if (i<MAX_SG_DUMP)
			peer_dbg("nv_dma_map -- %d 0x%016llx %u\n", i, sg->dma_address, sg->dma_length);
	}
#endif
	peer_dbg("nv_mem_context:%px page_table:%px dma_mapping:%px is_callback:%d\n", nv_mem_context, nv_mem_context->page_table, nv_mem_context->dma_mapping, READ_ONCE(nv_mem_context->is_callback));

	*nmap = nv_mem_context->npages;
 out:
	spin_unlock_irqrestore(&ctx_list.lock, flags);
	return ret;
}

static int nv_dma_unmap(struct sg_table *sg_head, void *context,
			   struct device  *dma_device)
{
	int ret = 0;
	struct nv_mem_context *nv_mem_context =
		(struct nv_mem_context *) context;
	struct pci_dev *pci_device = dma_to_pci_dev(dma_device);
	unsigned long flags;
	
	if (!nv_mem_context) {
		peer_err("invalid context\n");
		return -EINVAL;
	}
	if (!pci_device) {
		peer_err("invalid pci_device\n");
		return -EINVAL;		
	}

	spin_lock_irqsave(&ctx_list.lock, flags);
	if (!__ctxlist_is_tracked(nv_mem_context)) {
		peer_err("error, context %px not tracked, ignoring it\n", nv_mem_context);
		ret = -EAGAIN;
		goto out;
	}

	peer_dbg("nv_mem_context:%px page_table:%px dma_mapping:%px is_callback:%d\n", nv_mem_context, nv_mem_context->page_table, nv_mem_context->dma_mapping, READ_ONCE(nv_mem_context->is_callback));
	
	if (READ_ONCE(nv_mem_context->is_callback)) {
		// do nothing
		ret = 0;
		goto out;
	}

	if (!nv_mem_context->sg_allocated) {
		peer_err("error, sg is not allocated\n");
		ret = -EINVAL;
		goto out;
	}

#if NV_DMA_MAPPING
	if (nv_mem_context->dma_mapping) {
		//peer_dbg("freeing dma_mapping %px\n", nv_mem_context->dma_mapping);
		nv_dma_unmap_pages(pci_device, nv_mem_context->page_table, nv_mem_context->dma_mapping);
		nv_mem_context->dma_mapping = NULL;
	}
#endif

out:
	spin_unlock_irqrestore(&ctx_list.lock, flags);
	return ret;
}


static void nv_mem_put_pages(struct sg_table *sg_head, void *context)
{
	int ret = 0;
	struct nv_mem_context *nv_mem_context =
		(struct nv_mem_context *) context;
	unsigned long flags;

	if (!nv_mem_context) {
		peer_err("invalid context %px\n", nv_mem_context);
		return;
	}

	spin_lock_irqsave(&ctx_list.lock, flags);
	if (!__ctxlist_is_tracked(nv_mem_context)) {
		peer_err("error, context %px not tracked, ignoring it\n", nv_mem_context);
		goto out;
	}

	peer_dbg("nv_mem_context:%px page_table:%px is_callback:%d\n", nv_mem_context, nv_mem_context->page_table, READ_ONCE(nv_mem_context->is_callback));
	
	// freeing table even in the invalidation callback case
	if (nv_mem_context->sg_allocated) {
		sg_free_table(sg_head);
		nv_mem_context->sg_allocated = 0;
	}

	if (READ_ONCE(nv_mem_context->is_callback))
		goto out;

	ret = nv_put_pages(0, 0, nv_mem_context->page_virt_start,
				   nv_mem_context->page_table);

#ifdef _DEBUG_ONLY_
	/* Here we expect an error in real life cases that should be ignored - not printed.
	  * (e.g. concurrent callback with that call)
	*/
	if (ret < 0) {
		printk(KERN_ERR "error %d while calling nvidia_p2p_put_pages, page_table=%px\n",
			ret,  nv_mem_context->page_table);
	}
#endif
	nv_mem_context->page_table = NULL;

out:
	spin_unlock_irqrestore(&ctx_list.lock, flags);
	return;
}

static void nv_mem_release(void *context)
{
	struct nv_mem_context *nv_mem_context =
		(struct nv_mem_context *) context;
	peer_dbg("nv_mem_context:%px page_table:%px dma_mapping:%px is_callback:%d\n", nv_mem_context, nv_mem_context->page_table, nv_mem_context->dma_mapping, READ_ONCE(nv_mem_context->is_callback));
	ctxlist_del(nv_mem_context);
	kfree(nv_mem_context);
	module_put(THIS_MODULE);
	return;
}

static int nv_mem_get_pages(unsigned long addr,
			  size_t size, int write, int force,
			  struct sg_table *sg_head,
			  void *client_context,
			  u64 core_context)
{
	int ret = 0;
	struct nv_mem_context *nv_mem_context = (struct nv_mem_context *)client_context;
	unsigned long flags;

	if (!nv_mem_context) {
		peer_err("invalid context\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&ctx_list.lock, flags);
	if (!__ctxlist_is_tracked(nv_mem_context)) {
		peer_err("error, context %px not tracked, ignoring it\n", nv_mem_context);
		ret = -EINVAL;
		goto out;
	}

	peer_dbg("nv_mem_context:%px page_table:%px dma_mapping:%px is_callback:%d\n", nv_mem_context, nv_mem_context->page_table, nv_mem_context->dma_mapping, READ_ONCE(nv_mem_context->is_callback));
	BUG_ON(nv_mem_context->is_callback);

	nv_mem_context->core_context = (void *)core_context;
	nv_mem_context->page_size = GPU_PAGE_SIZE;

	// deadlock if call below were to generate a callback
	ret = nv_get_pages(0, 0, nv_mem_context->page_virt_start, nv_mem_context->mapped_size,
			&nv_mem_context->page_table, nv_get_p2p_free_callback, nv_mem_context);
	if (ret < 0) {
		peer_err("nv_mem_get_pages -- error %d while calling nvidia_p2p_get_pages()\n", ret);
	}
	/* No extra access to nv_mem_context->page_table here as we are
	    called not under a lock and may race with inflight invalidate callback on that buffer.
	    Extra handling was delayed to be done under nv_dma_map.
	 */
 out:
	spin_unlock_irqrestore(&ctx_list.lock, flags);
	return ret;
}


static unsigned long nv_mem_get_page_size(void *context)
{
	struct nv_mem_context *nv_mem_context =
				(struct nv_mem_context *)context;

	return nv_mem_context->page_size;

}


static struct peer_memory_client nv_mem_client = {
	.acquire		= nv_mem_acquire,
	.get_pages	= nv_mem_get_pages,
	.dma_map	= nv_dma_map,
	.dma_unmap	= nv_dma_unmap,
	.put_pages	= nv_mem_put_pages,
	.get_page_size	= nv_mem_get_page_size,
	.release		= nv_mem_release,
};

static int __init nv_mem_client_init(void)
{
	strcpy(nv_mem_client.name, DRV_NAME);
	strcpy(nv_mem_client.version, DRV_VERSION);

        peer_info("loading %s:%s\n", DRV_NAME, DRV_VERSION);

	ctxlist_init();

        if (load_nv_symbols())
                return -EINVAL;

	reg_handle = ib_register_peer_memory_client(&nv_mem_client,
					     &mem_invalidate_callback);
	if (!reg_handle) {
                unload_nv_symbols();
		return -EINVAL;
        }
	return 0;
}

static void __exit nv_mem_client_cleanup(void)
{
        peer_info("unloading %s:%s\n", DRV_NAME, DRV_VERSION);
	ib_unregister_peer_memory_client(reg_handle);
	if (!ctxlist_is_empty()) {
		peer_err("error, ctx list not empty\n");
	}
        unload_nv_symbols();
}

module_init(nv_mem_client_init);
module_exit(nv_mem_client_cleanup);
