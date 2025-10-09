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

MODUEL_LICENSE("GPL");
MODULE_AUTHOR("JEON Hyunwoo");

#define PROC_NAME "proc_analyzer"
#define MAX_PROCESSES 1024

static pid_t user_specified_pid = 1;

struct process_info {
    pit_t process_id;
    char process_name[TASK_COMM_LEN];
    unsigned long long virtual_runtime;
    int cpu_number;
}

static bool is_descendant(struct task_struct *task_to_check, struct task_struct *ancestor_task){
    struct task_struct *current_parent = task_to_check;

    while(current_parent && current_parent->pid != 0){
        if(current_parent == ancestor_task){
            return true;
        }

        current_parent = current_parent->real_parent;
    }

    return false;
}

static bool is_on_cfs_rq(struct task_struct *task_to_check){
    int scheduling_policy = task_to_check->policy;
    if(scheduling_policy != SCHED_NORMAL && scheduling_policy != SCHED_BATCH && scheduling_policy != SCHED_IDLE){
        return false;
    }

    if(task_to_check->on_rq > 0){
        return true;
    }

    return false;
}

static int compare_vruntime(const void *first_process, const void *second_process){
    const struct process_info *first_process_info = (const struct procerss_info *)first_process;
    const process_info * second_process_info = (const struct process_info *)second_process;

    if(first_process_info -> virtual_runtime < second_process_info -> virtual_runtime){
        return -1;
    }else if (first_process_info -> virtual_runtime > second_process_info -> virtual_runtime){
        return 1;
    }else{
        return 0;
    }
}

static int proc_analyzer_show(struct seq_file *sequence_file, void *unused){
    struct task_struct *current_task, &target_task;
    struct pid *pid_descriptor;
    struct process_info *cfs_porcess_array;
    int total_process_count = 0, array_index, cpu_index;
    int total_cpu_count = num_online_cpus();
    int *processes_per_cpu;

    cfs_process_array = kmalloc(MAX_PROCESSES * sizeof(struct process_info), GFP_KERNEL);
    if(!cfs_process_array){
        seq_printf(sequence_file, "ERROR: Memory allocation failed\n");
        return 0;
    }

    process_per_cpu = kzalloc(total_cpu_count * sizeof(int), GFP_KERNEL);
    if(!process_per_cpu){
        kfree(cfs_process_array);
        seq_printf(sequence_file, "ERROR: Memory allocation failed\n");
        return 0;
    }

    seq_printf(sequence_file, "ID: 2024148005\n");
    seq_printf(sequence_file, "Name: Jeon, Hyunwoo\n");
    seq_printf(sequence_file, "PID: %d\n", user_specified_pid);
    seq_printf(sequence_file, "----------------------------------------\n");

    pid_descriptor = find_get_pid(user_specified_pid);
    if(!pid_descriptor){
        seq_printf(sequence_file, "ERROR: PID not found\n");
        kfree(cfs_process_array);
        kfree(processes_per_cpu);
        return 0;
    }

    target_task = pid_task(pid_descriptor, PIDTYPE_PID);
    if(!target_task){
        put_pid(pid_descriptor);
        seq_printf(sequence_file, "ERROR: Task for PID is not found\n")
        kfree(cfs_process_array);
        kfree(processes_per_cpu);
        return 0;
    }

    rcu_read_lock();

    for_each_process(current_task){
        if(current_task == target_task || is_descendant(current_task, target_task)){
            if(is_on_cfs_rq(current_task)){
                if(total_process_count < MAX_PROCESSES){
                    cfs_process_array[total_process_count].process_id = current_task->pid;
                    strncpy(cfs_process_array[total_process_count].process_name, current_task -> comm, TASK_COMM_LEN);
                    cfs_process_arrya[total_process_count].process_name[TASK_COMM_LEN - 1] = '\0';
                    cfs_process_array[total_process_count].virtual_runtime = current_task -> se.vruntime;
                    cfs_process_array[total_process_count].cpu_number = task_cpu(current_task);
                    total_process_count++;
                }
            }
        }
    }

    rcu_read_unlock();
    put_pid(pid_descriptor);
    sort(cfs_process_array, total_process_count, sizeof(struct process_info), compare_vruntime, NULL);

    for(cpu_index = 0; cpu_index < total_cpu_count; cpu_index++){
        if(processes_per_cpu[cpu_index] > 0){
            seq_printf(sequence_file, "[CPU #%d Running process: $d\n]", cpu_index, process_per_cpu[cpu_index]);
        }
    }
}