/*
 *  linux/fs/ext4/fsync.c
 *
 * 
 *
 *  Copyright (C) 1993  Stephen Tweedie (sct@redhat.com)
 *  from
 *  Copyright (C) 1992  Remy Card (card@masi.ibp.fr)
 *                      Laboratoire MASI - Institut Blaise Pascal
 *                      Universite Pierre et Marie Curie (Paris VI)
 *  from
 *  linux/fs/minix/truncate.c   Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext4fs fsync primitive
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 *  Removed unnecessary code duplication for little endian machines
 *  and excessive __inline__s.
 *        Andi Kleen, 1997
 *
 * Major simplications and cleanup - we only need to do the metadata, because
 * we can depend on generic_block_fdatasync() to sync the data blocks.
 *
 */

/*
 * Implement SpanFS based on Ext4.
 * Copyright (C) 2013-2016  Junbin Kang <kangjb@act.buaa.edu.cn>, Benlong Zhang <zblgeqian@gmail.com>, Lian Du <dulian@act.buaa.edu.cn>.
 * Beihang University
 */
 
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/writeback.h>
#include <linux/jbd2.h>
#include <linux/blkdev.h>
#include <linux/kernel.h>

#include "eext4.h"
#include "ext4.h"
#include "ext4_jbd2.h"

#include <trace/events/ext4.h>

/*
 * If we're not journaling and this is a just-created file, we have to
 * sync our parent directory (if it was freshly created) since
 * otherwise it will only be written by writeback, leaving a huge
 * window during which a crash may lose the file.  This may apply for
 * the parent directory's parent as well, and so on recursively, if
 * they are also freshly created.
 */
static int ext4_sync_parent(struct inode *inode)
{
	struct dentry *dentry = NULL;
	struct inode *next;
	int ret = 0;

	if (!ext4_test_inode_state(inode, EXT4_STATE_NEWENTRY))
		return 0;
	inode = igrab(inode);
	while (ext4_test_inode_state(inode, EXT4_STATE_NEWENTRY)) {
		ext4_clear_inode_state(inode, EXT4_STATE_NEWENTRY);
		dentry = d_find_any_alias(inode);
		if (!dentry)
			break;
		next = igrab(dentry->d_parent->d_inode);
		dput(dentry);
		if (!next)
			break;
		iput(inode);
		inode = next;
		ret = sync_mapping_buffers(inode->i_mapping);
		if (ret)
			break;
		ret = sync_inode_metadata(inode, 1);
		if (ret)
			break;
	}
	iput(inode);
	return ret;
}

static int generic_inode_sync(struct inode *inode, loff_t start, loff_t end, int datasync)
{

	int err;
	int ret;

	err = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (err)
		return err;

	
	ret = sync_mapping_buffers(inode->i_mapping);
	if (!(inode->i_state & I_DIRTY))
		goto out;
	if (datasync && !(inode->i_state & I_DIRTY_DATASYNC))
		goto out;

	err = sync_inode_metadata(inode, 1);
	if (ret == 0)
		ret = err;

out:

	if(ret)
		return ret;
	
	return blkdev_issue_flush(inode->i_sb->s_bdev, GFP_KERNEL, NULL);

}

static int sync_dir(struct inode *inode, loff_t start, loff_t end, int datasync, int *tid)
{
	
	struct ext4_inode_info *ei = EXT4_I(inode);
	journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;
	int ret = 0, err;
	tid_t commit_tid;
	bool needs_barrier = false;
	
	
	J_ASSERT(ext4_journal_current_handle() == NULL);

	
	if (inode->i_sb->s_flags & MS_RDONLY) {
		/* Make sure that we read updated s_mount_flags value */
		smp_rmb();
		if (EXT4_SB(inode->i_sb)->s_mount_flags & EXT4_MF_FS_ABORTED)
			ret = -EROFS;
		goto out;
	}

	if (!journal) {
		ret = generic_inode_sync(inode, start, end, datasync);
		if (!ret && !hlist_empty(&inode->i_dentry))
			ret = ext4_sync_parent(inode);
		goto out;
	}

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	ASSERT(ret == 0);
	if (ret)
		return ret;
	/*
	 * data=writeback,ordered:
	 *  The caller's filemap_fdatawrite()/wait will sync the data.
	 *  Metadata is in the journal, we wait for proper transaction to
	 *  commit here.
	 *
	 * data=journal:
	 *  filemap_fdatawrite won't do anything (the buffers are clean).
	 *  ext4_force_commit will write the file data into the journal and
	 *  will wait on that.
	 *  filemap_fdatawait() will encounter a ton of newly-dirtied pages
	 *  (they were dirtied by commit).  But that's OK - the blocks are
	 *  safe in-journal, which is all fsync() needs to ensure.
	 */
	ASSERT(ext4_should_journal_data(inode));
	
	
	ret = jbd2_journal_start_commit(EXT4_SB(inode->i_sb)->s_journal, tid);
	if(ret == 1){
			
		ret = 0;
	}
		
	

out:
	
	return ret;

}

#define PATH_LEN 64
static int sync_parent(struct dentry *old_dentry)
{
	struct dentry *dentry = old_dentry;
	struct inode *next, *inode = dentry->d_inode;
	int ret = 0;
	int tid = -1;
	
	if(inode == eext4_rd_uvlroot->d_inode)
		return 0;
	
	if (!spanfs_test_inode_state(inode, ENTRY_NEW))
		return 0;

	while (spanfs_test_and_clear_inode_state(inode, ENTRY_NEW)) {
		

		dentry = dentry->d_parent;
		ASSERT(dentry != NULL);
		

		next = dentry->d_inode;
		ASSERT(next != NULL);
		tid = -1;
		ret = sync_dir(next, 0, LLONG_MAX, 0, &tid);
		if (ret){
			break;
		}
		
		spin_lock(&inode->i_lock);
		EXT4_I(inode)->i_tid = tid;
		spanfs_set_inode_state(inode, ENTRY_COMMITTED);
		spin_unlock(&inode->i_lock);
		
		inode = next;
		
		if(inode == eext4_rd_uvlroot->d_inode)
			break;
		
	}

	return ret;
}

static int sync_parent_again(struct dentry *old_dentry)
{
	struct dentry *dentry = old_dentry;
	struct inode *next, *inode = dentry->d_inode;
	int ret = 0;
	struct inode *inode_stack[PATH_LEN];
	int top = 0;
	
		
	if(inode == eext4_rd_uvlroot->d_inode)
		return 0;


start_sync:
	while (!spanfs_test_inode_state(inode, ENTRY_PERSISTENT)) {
	
		dentry = dentry->d_parent;
		ASSERT(dentry != NULL);
		next = dentry->d_inode;
		
		ASSERT(next != NULL);
		spin_lock(&inode->i_lock);
		if(EXT4_I(inode)->i_tid != -1){
			spin_unlock(&inode->i_lock);
			ret = jbd2_log_wait_commit(EXT4_SB(next->i_sb)->s_journal, EXT4_I(inode)->i_tid);
			if(ret)
				break;
		}else if(!spanfs_test_inode_state(inode, ENTRY_COMMITTED)){
			spin_unlock(&inode->i_lock);
			ret = ext4_force_commit(next->i_sb);
			if(ret)
				break;
			
		}else
			spin_unlock(&inode->i_lock);

		inode_stack[top++] = inode;

		inode = next;
			
		if(inode == eext4_rd_uvlroot->d_inode)
			break;
			
	}
	
out:
	if(!ret){
		int i;
		for(i = 0; i < top; i++)
			spanfs_set_inode_state(inode_stack[i], ENTRY_PERSISTENT);

	}
	return ret;

}



/*
 * akpm: A new design for ext4_sync_file().
 *
 * This is only called from sys_fsync(), sys_fdatasync() and sys_msync().
 * There cannot be a transaction open by this task.
 * Another task could have dirtied this inode.  Its data can be in any
 * state in the journalling system.
 *
 * What we do is just kick off a commit and wait on it.  This will snapshot the
 * inode to disk.
 */

int ext4_sync_file(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct ext4_inode_info *ei = EXT4_I(inode);
	journal_t *journal = EXT4_SB(inode->i_sb)->s_journal;
	int ret = 0, err;
	tid_t commit_tid;
	bool needs_barrier = false;
	struct dentry *dentry = file->f_dentry;
	
	J_ASSERT(ext4_journal_current_handle() == NULL);

	trace_ext4_sync_file_enter(file, datasync);

	if (inode->i_sb->s_flags & MS_RDONLY) {
		/* Make sure that we read updated s_mount_flags value */
		smp_rmb();
		if (EXT4_SB(inode->i_sb)->s_mount_flags & EXT4_MF_FS_ABORTED)
			ret = -EROFS;
		goto out;
	}

	if (!journal) {
		ret = generic_file_fsync(file, start, end, datasync);
		if (!ret && !hlist_empty(&inode->i_dentry))
			ret = ext4_sync_parent(inode);
		goto out;
	}
	ASSERT(dentry == file->f_dentry);
	ret = sync_parent(dentry);
	if(ret)
		goto out;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;
	/*
	 * data=writeback,ordered:
	 *  The caller's filemap_fdatawrite()/wait will sync the data.
	 *  Metadata is in the journal, we wait for proper transaction to
	 *  commit here.
	 *
	 * data=journal:
	 *  filemap_fdatawrite won't do anything (the buffers are clean).
	 *  ext4_force_commit will write the file data into the journal and
	 *  will wait on that.
	 *  filemap_fdatawait() will encounter a ton of newly-dirtied pages
	 *  (they were dirtied by commit).  But that's OK - the blocks are
	 *  safe in-journal, which is all fsync() needs to ensure.
	 */
	if (ext4_should_journal_data(inode)) {
		ret = ext4_force_commit(inode->i_sb);
		ASSERT(dentry == file->f_dentry);
		err = sync_parent_again(dentry);
		if(!ret)
			ret = err;
		goto out;
	}

	commit_tid = datasync ? ei->i_datasync_tid : ei->i_sync_tid;
	if (journal->j_flags & JBD2_BARRIER &&
	    !jbd2_trans_will_send_data_barrier(journal, commit_tid))
		needs_barrier = true;
	ret = jbd2_complete_transaction(journal, commit_tid);
	if (needs_barrier) {
		err = blkdev_issue_flush(inode->i_sb->s_bdev, GFP_KERNEL, NULL);
		if (!ret)
			ret = err;
	}
	ASSERT(dentry == file->f_dentry);
	err = sync_parent_again(dentry);
	if(!ret)
		ret = err;
	
out:
	trace_ext4_sync_file_exit(inode, ret);
	return ret;
}
