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
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/hugetlb.h>
#include <linux/atomic.h>


#include "nv-p2p.h"
#include <rdma/peer_mem.h>


#define DRV_NAME	"nv_mem"
#define DRV_VERSION	"1.0"
#define DRV_RELDATE	__DATE__

#define peer_err(FMT, ARGS...)  printk(KERN_ERR   DRV_NAME " %s:%d " FMT, __FUNCTION__, __LINE__, ## ARGS)
#define peer_info(FMT, ARGS...) printk(KERN_INFO  DRV_NAME " %s:%d " FMT, __FUNCTION__, __LINE__, ## ARGS)
#define peer_dbg(FMT, ARGS...)  do { if (printk_ratelimit()) printk(KERN_DEBUG DRV_NAME " %s:%d " FMT, __FUNCTION__, __LINE__, ## ARGS); } while(0)


MODULE_AUTHOR("Yishai Hadas");
MODULE_DESCRIPTION("NVIDIA GPU memory plug-in");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

#define GPU_PAGE_SHIFT   16
#define GPU_PAGE_SIZE    ((u64)1 << GPU_PAGE_SHIFT)
#define GPU_PAGE_OFFSET  (GPU_PAGE_SIZE-1)
#define GPU_PAGE_MASK    (~GPU_PAGE_OFFSET)


invalidate_peer_memory mem_invalidate_callback;
static void *reg_handle;

struct nv_mem_context {
	struct nvidia_p2p_page_table *page_table;
	void *core_context;
	u64 page_virt_start;
	u64 page_virt_end;
	size_t mapped_size;
	unsigned long npages;
	unsigned long page_size;
	int is_callback;
	int sg_allocated;
};


static void nv_get_p2p_free_callback(void *data)
{
	int ret = 0;
	struct nv_mem_context *nv_mem_context = (struct nv_mem_context *)data;
	struct nvidia_p2p_page_table *page_table = NULL;

	__module_get(THIS_MODULE);
	if (!nv_mem_context) {
		peer_err("nv_get_p2p_free_callback -- invalid nv_mem_context\n");
		goto out;
	}

	if (!nv_mem_context->page_table) {
		peer_err("nv_get_p2p_free_callback -- invalid page_table\n");
		goto out;
	}

	/* Save page_table locally to prevent it being freed as part of nv_mem_release
	    in case it's called internally by that callback.
	*/
	page_table = nv_mem_context->page_table;
	/* For now don't set nv_mem_context->page_table to NULL, 
	  * confirmed by NVIDIA that inflight put_pages with valid pointer will fail gracefully.
	*/

	ACCESS_ONCE(nv_mem_context->is_callback) = 1;
	(*mem_invalidate_callback) (reg_handle, nv_mem_context->core_context);
	ret = nvidia_p2p_free_page_table(page_table);
	if (ret)
		peer_err("nv_get_p2p_free_callback -- error %d while calling nvidia_p2p_free_page_table()\n", ret);

out:
	module_put(THIS_MODULE);
	return;

}

/* At that function we don't call IB core - no ticket exists */
static void nv_mem_dummy_callback(void *data)
{
	struct nv_mem_context *nv_mem_context = (struct nv_mem_context *)data;
	int ret = 0;

	__module_get(THIS_MODULE);

	ret = nvidia_p2p_free_page_table(nv_mem_context->page_table);
	if (ret)
		peer_err("nv_mem_dummy_callback -- error %d while calling nvidia_p2p_free_page_table()\n", ret);

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

        peer_info("addr=%lx size=%zu page_virt_start=%llx mapped_size=%zu\n", 
                  addr, size, nv_mem_context->page_virt_start, nv_mem_context->mapped_size);

	ret = nvidia_p2p_get_pages(0, 0, nv_mem_context->page_virt_start, nv_mem_context->mapped_size,
			&nv_mem_context->page_table, nv_mem_dummy_callback, nv_mem_context);

	if (ret < 0) {
                peer_err("nv_mem_acquire -- nvidia_p2p_get_pages error %d for addr=%lx\n", ret, addr);
		goto err;
        }

	ret = nvidia_p2p_put_pages(0, 0, nv_mem_context->page_virt_start,
				   nv_mem_context->page_table);
	if (ret < 0) {
		/* Not expected, however in case callback was called on that buffer just before
		    put pages we'll expect to fail gracefully (confirmed by NVIDIA) and return an error.
		*/
		peer_err("nv_mem_acquire -- error %d while calling nvidia_p2p_put_pages()\n", ret);
		goto err;
	}

	/* 1 means mine */
	*client_context = nv_mem_context;
	__module_get(THIS_MODULE);
	return 1;

err:
	kfree(nv_mem_context);

	/* Error case handled as not mine */
	return 0;
}

static int nv_dma_map(struct sg_table *sg_head, void *context,
			      struct device *dma_device, int dmasync,
			      int *nmap)
{
	int i, ret;
	struct scatterlist *sg;
	struct nv_mem_context *nv_mem_context =
		(struct nv_mem_context *) context;
	struct nvidia_p2p_page_table *page_table = nv_mem_context->page_table;

        if (!page_table) {
            peer_err("error, invalid p2p page table\n");
            return -EINVAL;
        }

	if (page_table->page_size != NVIDIA_P2P_PAGE_SIZE_64KB) {
		peer_err("error, assumption of 64KB pages failed size_id=%u\n",
			 page_table->page_size);
		return -EINVAL;
	}

	nv_mem_context->npages = PAGE_ALIGN(nv_mem_context->mapped_size) >>
						GPU_PAGE_SHIFT;

	if (nv_mem_context->page_table->entries != nv_mem_context->npages) {
		peer_err("error, unexpected number of page table entries got=%u, expected=%lu\n",
					nv_mem_context->page_table->entries,
					nv_mem_context->npages);
		return -EINVAL;
	}

	ret = sg_alloc_table(sg_head, nv_mem_context->npages, GFP_KERNEL);
	if (ret)
		return ret;

	nv_mem_context->sg_allocated = 1;
	for_each_sg(sg_head->sgl, sg, nv_mem_context->npages, i) {
		sg_set_page(sg, NULL, nv_mem_context->page_size, 0);
		sg->dma_address = page_table->pages[i]->physical_address;
		sg->dma_length = nv_mem_context->page_size;
	}

	*nmap = nv_mem_context->npages;
	return 0;
}

static int nv_dma_unmap(struct sg_table *sg_head, void *context,
			   struct device  *dma_device)
{
	return 0;
}


static void nv_mem_put_pages(struct sg_table *sg_head, void *context)
{
	int ret = 0;
	struct nv_mem_context *nv_mem_context =
		(struct nv_mem_context *) context;

	if (ACCESS_ONCE(nv_mem_context->is_callback))
		goto out;

	ret = nvidia_p2p_put_pages(0, 0, nv_mem_context->page_virt_start,
				   nv_mem_context->page_table);

#ifdef _DEBUG_ONLY_
	/* Here we expect an error in real life cases that should be ignored - not printed.
	  * (e.g. concurrent callback with that call)
	*/
	if (ret < 0) {
		printk(KERN_ERR "error %d while calling nvidia_p2p_put_pages, page_table=%p \n",
			ret,  nv_mem_context->page_table);
	}
#endif


out:
	if (nv_mem_context->sg_allocated)
		sg_free_table(sg_head);

	return;
}

static void nv_mem_release(void *context)
{
	struct nv_mem_context *nv_mem_context =
		(struct nv_mem_context *) context;

	kfree(nv_mem_context);
	module_put(THIS_MODULE);
	return;
}

static int nv_mem_get_pages(unsigned long addr,
			  size_t size, int write, int force,
			  struct sg_table *sg_head,
			  void *client_context,
			  void *core_context)
{
	int ret;
	struct nv_mem_context *nv_mem_context;

	nv_mem_context = (struct nv_mem_context *)client_context;
	if (!nv_mem_context)
		return -EINVAL;

        peer_info("addr=%lx size=%zu\n", addr, size);

	nv_mem_context->core_context = core_context;
	nv_mem_context->page_size = GPU_PAGE_SIZE;

	ret = nvidia_p2p_get_pages(0, 0, nv_mem_context->page_virt_start, nv_mem_context->mapped_size,
			&nv_mem_context->page_table, nv_get_p2p_free_callback, nv_mem_context);
	if (ret < 0) {
		peer_err("nv_mem_get_pages -- error %d while calling nvidia_p2p_get_pages()\n", ret);
		return ret;
	}

	/* No extra access to nv_mem_context->page_table here as we are
	    called not under a lock and may race with inflight invalidate callback on that buffer.
	    Extra handling was delayed to be done under nv_dma_map.
	 */
	return 0;
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

	reg_handle = ib_register_peer_memory_client(&nv_mem_client,
					     &mem_invalidate_callback);
	if (!reg_handle)
		return -EINVAL;

	return 0;
}

static void __exit nv_mem_client_cleanup(void)
{
        peer_info("unloading %s:%s\n", DRV_NAME, DRV_VERSION);
	ib_unregister_peer_memory_client(reg_handle);
}

module_init(nv_mem_client_init);
module_exit(nv_mem_client_cleanup);
