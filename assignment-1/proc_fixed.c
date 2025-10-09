#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/smp.h>
#include <linux/rcupdate.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JEON Hyunwoo");

#define PROC_NAME "proc_analyzer"
#define MAX_PROCESSES 1024

static pid_t user_specified_pid = 1;
static struct proc_dir_entry *proc_entry;

struct process_info {
    pid_t pid;
    char comm[TASK_COMM_LEN];
    u64 vruntime;
    int cpu;
};

static bool is_descendant(struct task_struct *t, struct task_struct *ancestor)
{
    while (t && READ_ONCE(t->pid) != 0) {
        if (t == ancestor)
            return true;
        t = rcu_dereference(t->real_parent);
    }
    return false;
}

static bool is_cfs_enqueued(const struct task_struct *p)
{
    int pol = READ_ONCE(p->policy);
    if (pol != SCHED_NORMAL && pol != SCHED_BATCH && pol != SCHED_IDLE)
        return false;
    /* Only count tasks that are actually enqueued on the CFS runqueue */
    return READ_ONCE(p->se.on_rq);
}

static int cmp_vruntime(const void *a, const void *b)
{
    const struct process_info *pa = a;
    const struct process_info *pb = b;

    if (pa->vruntime < pb->vruntime)
        return -1;
    if (pa->vruntime > pb->vruntime)
        return 1;
    return 0;
}

static int proc_analyzer_show(struct seq_file *m, void *v)
{
    struct task_struct *p, *target;
    struct pid *kpid;
    struct process_info *arr;
    int *per_cpu_cnt;
    int total = 0;
    int cpu, i;
    int nr_cpus = num_online_cpus();
    pid_t pid = READ_ONCE(user_specified_pid);

    arr = kmalloc_array(MAX_PROCESSES, sizeof(*arr), GFP_KERNEL);
    if (!arr) {
        seq_puts(m, "ERROR: Memory allocation failed\n");
        return 0;
    }
    per_cpu_cnt = kcalloc(nr_cpus, sizeof(*per_cpu_cnt), GFP_KERNEL);
    if (!per_cpu_cnt) {
        kfree(arr);
        seq_puts(m, "ERROR: Memory allocation failed\n");
        return 0;
    }

    seq_puts(m, "ID: 2024148005\n");
    seq_puts(m, "Name: Jeon, Hyunwoo\n");
    seq_printf(m, "PID: %d\n", pid);
    seq_puts(m, "----------------------------------------\n");

    kpid = find_get_pid(pid);
    if (!kpid) {
        seq_puts(m, "ERROR: PID not found\n");
        goto out;
    }

    rcu_read_lock();
    target = pid_task(kpid, PIDTYPE_PID);
    if (!target) {
        rcu_read_unlock();
        put_pid(kpid);
        seq_puts(m, "ERROR: Task for PID is not found\n");
        goto out;
    }

    for_each_process(p) {
        if (p == target || is_descendant(p, target)) {
            if (is_cfs_enqueued(p)) {
                if (total < MAX_PROCESSES) {
                    arr[total].pid = READ_ONCE(p->pid);
                    strscpy(arr[total].comm, p->comm, TASK_COMM_LEN);
                    arr[total].vruntime = READ_ONCE(p->se.vruntime);
                    arr[total].cpu = task_cpu(p);
                    if (arr[total].cpu >= 0 && arr[total].cpu < nr_cpus)
                        per_cpu_cnt[arr[total].cpu]++;
                    total++;
                }
            }
        }
    }
    rcu_read_unlock();
    put_pid(kpid);

    sort(arr, total, sizeof(arr[0]), cmp_vruntime, NULL);

    for (cpu = 0; cpu < nr_cpus; cpu++) {
        if (per_cpu_cnt[cpu] > 0) {
            seq_printf(m, "[CPU #%d] Running processes: %d\n", cpu, per_cpu_cnt[cpu]);
            for (i = 0; i < total; i++) {
                if (arr[i].cpu == cpu) {
                    seq_printf(m, "[%d] %s %llu\n",
                               arr[i].pid,
                               arr[i].comm,
                               (unsigned long long)arr[i].vruntime);
                }
            }
            seq_puts(m, "----------------------------------------\n");
        }
    }

out:
    kfree(arr);
    kfree(per_cpu_cnt);
    return 0;
}

static int proc_analyzer_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_analyzer_show, NULL);
}

static ssize_t proc_analyzer_write(struct file *file, const char __user *ubuf,
                                   size_t len, loff_t *ppos)
{
    char buf[32];
    int ret;
    int val;

    if (len == 0 || len >= sizeof(buf))
        return -EINVAL;

    if (copy_from_user(buf, ubuf, len))
        return -EFAULT;
    buf[len] = '\0';

    ret = kstrtoint(buf, 10, &val);
    if (ret)
        return ret;
    if (val <= 0)
        return -EINVAL;

    WRITE_ONCE(user_specified_pid, (pid_t)val);
    pr_info("proc_analyzer: PID set to %d\n", val);
    return len;
}

static const struct proc_ops proc_analyzer_ops = {
    .proc_open    = proc_analyzer_open,
    .proc_read    = seq_read,
    .proc_write   = proc_analyzer_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init proc_analyzer_init(void)
{
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &proc_analyzer_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }
    pr_info("proc_analyzer loaded. /proc/%s created.\n", PROC_NAME);
    return 0;
}

static void __exit proc_analyzer_exit(void)
{
    if (proc_entry)
        proc_remove(proc_entry);
    pr_info("proc_analyzer unloaded. /proc/%s removed.\n", PROC_NAME);
}

module_init(proc_analyzer_init);
module_exit(proc_analyzer_exit);
