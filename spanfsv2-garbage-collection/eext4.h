#ifndef _LINUX_EEXT4_H
#define _LINUX_EEXT4_H

/*
 * Implement SpanFS based on Ext4.
 * Copyright (C) 2013-2016  Junbin Kang <kangjb@act.buaa.edu.cn>, Benlong Zhang <zblgeqian@gmail.com>, Lian Du <dulian@act.buaa.edu.cn>.
 * Beihang University
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/path.h>


#include "ext4_jbd2.h"

extern int EEXT4_ONLINE_DEVICE_NUM;
extern int CPU_CORE_NUM;

#define EEXT4_SPANDIR_NUM 128

#define RANDOM_FACTOR (EEXT4_SPANDIR_NUM / CPU_CORE_NUM)
//#define EEXT4_DEBUG 1

#define EEXT4_DEVICE_NUM_MIN	1
#define EEXT4_DEVICE_NUM_MAX	128

//rename constants
#define EEXT4_DEVICE_MASK_MASK	0x3f
#define EEXT4_RENAME_TAG_NULL	0x00
#define EEXT4_RENAME_TAG_COMMON	0x80
#define EEXT4_RENAME_TAG_NEWENTRY	0x40

#define EEXT4_LOCAL 0
#define EEXT4_REMOTE 1

#define EEXT4_TAG	2


//#define DEBUG

struct eext4_entry_info {
	struct dentry	*spandir_dentry;
};
	
//represents an eext4 device
struct eext4_device {
	struct super_block	*sb;

	struct dentry		*device_root;
	struct dentry		**SPANDir;
	int					nr;
	struct block_device bdev;
	struct inode *bd_inode;
	//struct inode		*device_root_inode;

	struct lock_class_key bdev_inode_mutex_class;
	struct lock_class_key bdev_inode_lock_class;
};

/*the convenient structure for parameter passing in the eext4_rename routine*/
struct eext4_four_devices {
	char	old_dir_device;
	char	old_inode_device;
	char	new_dir_device;
	char	new_inode_device;
	void * 	saved_info;
};

/* super.c */
//the device array;
extern struct eext4_device	*eext4_devices[EEXT4_DEVICE_NUM_MAX];
extern struct dentry* eext4_rd_uvlroot;
extern const char *partition_opt;
extern const int partition_opt_len;
extern unsigned int round_robin_counter;

//eext4_inode_lookup reverse dentry list
struct dentry_node {
	struct dentry *dentry;
	struct dentry_node *next;
};

//get the device number of the directory;
#define EEXT4_INODE_DEVICE(inode) \
	(EXT4_SB (inode->i_sb)->eext4_sb_info_id)



#define ASSERT(expr)						\
		if (unlikely(!(expr))) {				\
			printk(KERN_ERR "\nAssertion failure in %s() "	\
						"at line %d:\n\n"	\
					"\trbd_assert(%s);\n\n",	\
					__func__, __LINE__, #expr);	\
			BUG();						\
		}


static inline int get_span_index(void) {
	unsigned char tmp;
	
	get_random_bytes(&tmp, sizeof(unsigned char));
	tmp = tmp % RANDOM_FACTOR;
	return task_cpu(current) + tmp * CPU_CORE_NUM;
}
	

static struct eext4_device *eext4_alloc_device (void) {
	return (struct eext4_device*) kzalloc(sizeof (struct eext4_device), GFP_KERNEL);
}

static void eext4_kfree_device (struct eext4_device *device) {
	kfree (device);
}

//Here eext4 decides now where to put the new object;
//whether by the current cpu number, or incorporating the 
//round-robin manner with a global counter;
static char eext4_placement_police (struct inode *inode) {
	//return ((round_robin_counter++) % EEXT4_ONLINE_DEVICE_NUM);
	return ((EXT4_I(inode)->i_rr_counter++) % EEXT4_ONLINE_DEVICE_NUM);
}

static inline struct inode *eext4_find_spandir(struct dentry **spandir, u32 spandir_ino)
{
	int nr = EEXT4_SPANDIR_NUM;
	int i;
	
	//eext4_warning("spandir number %d pino %d\n", nr, spandir_ino);
	ASSERT(spandir_ino - 11 < EEXT4_SPANDIR_NUM);
	ASSERT(spandir_ino >= 11);
	return spandir[spandir_ino - 11]->d_inode;
}

static void eext4_warning(const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	
#ifdef EEXT4_DEBUG
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	printk(KERN_WARNING "SpanFS: %pV", &vaf);

	va_end(args);
#endif
}

static int eext4_deviceid_valid (__u8 device) {
	return device >= EEXT4_DEVICE_NUM_MIN && device <= EEXT4_ONLINE_DEVICE_NUM;
}

static struct inode * eext4_map_spandir (__u8 remote_device) {
	if (!eext4_deviceid_valid (remote_device + 1))
		eext4_warning("eext4_map_spandir deviceid invalid: %u\n", remote_device);

	return eext4_devices[remote_device]->SPANDir[get_span_index()]->d_inode;
}

static void eext4_get_spandir (struct inode *spandir) {
	mutex_lock_nested (&spandir->i_mutex, I_MUTEX_PARENT2);
}

static void eext4_put_spandir (struct inode *spandir) {
	mutex_unlock (&spandir->i_mutex);
}

static void eext4_sync_dir (struct inode *dir, unsigned int *i_flags) {
	*i_flags = dir->i_flags;
	dir->i_flags |= S_DIRSYNC;
}

static void eext4_unsync_dir (struct inode *dir, unsigned int *i_flags) {
	dir->i_flags = *i_flags;
}

/*check whether the entry matches in the three fields: device_mask, pinode, inode
**it seems that the chat type is signed!!
**130 in __u8: 10000010 when passed in could be intepreted as -01111110, which is -126
**/
static int eext4_entry_match (struct ext4_dir_entry_2 *de, __u8 device_mask, unsigned long pinode, unsigned long inode) {
	if (de->device_mask == device_mask && 
		le32_to_cpu (de->pinode) == pinode &&
		le32_to_cpu (de->inode) == inode)
		return 1;

	printk(KERN_ERR "entry match failed\n");
	return 0;
}

static int eext4_ordered_submission_journal_stop (handle_t *handle) {
	ext4_handle_sync(handle);
	return ext4_journal_stop(handle);
}

extern struct dentry *lookup_one_len (const char *name, struct dentry *base, int len);

/* namei.c  */
extern struct dentry *eext4_lookup_one_len (struct dentry *dentry, const char *name);



typedef int (*gc_filldir_t)(void *, const char *, int, loff_t, u64, u64, u64, unsigned);
struct gc_dir_context {
	const gc_filldir_t actor;
	loff_t pos;
};

struct gc_file {
	
	struct inode *f_inode;
	fmode_t		f_mode;
	loff_t		f_pos;
	void 		*private_data;
	u64			f_version;
	struct file_ra_state	f_ra;

};

static inline bool dir_emit_for_gc(struct gc_dir_context *ctx,
			    const char *name, int namelen,
			    u64 ino, u64 pino, u64 device_mask, unsigned type)
{
	return ctx->actor(ctx, name, namelen, ctx->pos, ino, pino, device_mask, type) == 0;
}


/* dir.c */
extern int __ext4_check_dir_entry_for_gc(const char *, unsigned int, struct inode *,
				  struct gc_file *,
				  struct ext4_dir_entry_2 *,
				  struct buffer_head *, char *, int,
				  unsigned int);
#define ext4_check_dir_entry_for_gc(dir, filp, de, bh, buf, size, offset)	\
	unlikely(__ext4_check_dir_entry_for_gc(__func__, __LINE__, (dir), (filp), \
					(de), (bh), (buf), (size), (offset)))

extern int htree_inlinedir_to_tree_for_gc(struct gc_file *dir_file,
				   struct inode *dir, ext4_lblk_t block,
				   struct dx_hash_info *hinfo,
				   __u32 start_hash, __u32 start_minor_hash,
				   int *has_inline_data);

extern int ext4_htree_store_dirent_for_gc(struct gc_file *dir_file, __u32 hash,
				    __u32 minor_hash,
				    struct ext4_dir_entry_2 *dirent);

extern int ext4_htree_fill_tree_for_gc(struct gc_file *dir_file, __u32 start_hash,
			 __u32 start_minor_hash, __u32 *next_hash);

extern int ext4_read_inline_dir_for_gc(struct gc_file *file,
			 struct gc_dir_context *ctx,
			 int *has_inline_data);

extern struct inode * eext4_local_entry_valid (struct inode *dir, struct ext4_dir_entry_2 *de, struct ext4_dir_entry_2 **remote_de);

extern int eext4_delete_entry_fast (struct inode *dir, struct ext4_dir_entry_2 *de, struct buffer_head *bh, int sync);

extern int eext4_delete_entry_slow (struct inode *dir, struct ext4_dir_entry_2 *de);


//#define GC_ENABLED

#ifdef GC_ENABLED
extern unsigned long calculate_total(void);

extern void clear_counter(void);
#endif

#endif
