#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>

// 커널 모듈의 라이센스와 작성자 정보
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JEON Hyunwoo");

// proc 파일 시스템 파일 이름
#define PROC_NAME "ancestor"

// 사용자가 입력한 PID를 저장하는 변수
static pid_t user_specified_pid = 1;
// 조상 프로세스 포언터
static struct proc_dir_entry *ancestor_entry;

// 파일을 읽을 때 호출되는 함수
// 지정한 pid의 모든 조상 프로세스를 찾아 출력함
static int ancestor_show(struct seq_file *sequence_file, void *unused){
    // 현재 처리 중인 프로세스의 정보를 담은 구조체 모인터, for 문용 변수
    struct task_struct *current_task, *t;
    // PID를 나타내는 커널 내부 구조체 포인터
    struct pid *pid_descriptor;

    // 기본 정보 출력
    seq_printf(sequence_file, "ID: 2024148005\n");
    seq_printf(sequence_file, "Name: Jeon, Hyunwoo\n");
    seq_printf(sequence_file, "----------------------------------------\n");

    // pid 구조체를 찾고 참조 카운트를 증가시킴
    pid_descriptor = find_get_pid(user_specified_pid);
    if(!pid_descriptor){ // pid를 찾지 못한 경우 처리
        seq_printf(sequence_file, "ERROR: PID not found\n");
        return 0;
    }

    // pid 구조체에서 실제 프로세스 정보를 가져옴
    current_task = get_pid_task(pid_descriptor, PIDTYPE_PID);
    put_pid(pid_descriptor);

    if(!current_task){ // current_task 가 없을 경우 처리
        seq_printf(sequence_file, "ERROR: Task for PID not found\n");
        return 0;
    }

    // RCU 읽기 잠금 시작
    rcu_read_lock();

    // 부모 프로세스를 따라 올라가며 조상 프로세스를 찾음
    for(t = current_task; t && t -> pid != 0; t = rcu_dereference(t -> real_parent)){
        char comm[TASK_COMM_LEN];
        get_task_comm(comm, t);
        seq_printf(sequence_file, "[%d] %s\n", t -> pid, comm);
    }

    // RCU 읽기 잠금 해제
    rcu_read_unlock();

    put_task_struct(current_task);

    return 0;
}

// 파일을 열 때 호출되는 함수
static int ancestor_open(struct inode *inode_ptr, struct file *file_ptr){
    // ancestor_show를 실제 데이터 출력 함수로 등록
    return single_open(file_ptr, ancestor_show, NULL);
}

// 파일을 쓸 때 호출되는 함수
static ssize_t ancestor_write(struct file *file, const char __user *user_buffer, size_t len, loff_t *file_offset){
    int tmp;
    if(len == 0){
        return -EINVAL;
    }

    // 사용자의 입력을 정수로 변환
    if(kstrtoint_from_user(user_buffer, len, 10, &tmp)){
        return -EINVAL;
    }

    // 입력이 올바르지 않은 경우 처리
    if(tmp <= 0){
        return -EINVAL;
    }

    // 결과 반환
    user_specified_pid = (pid_t)tmp;
    pr_info("ancestor: PID set to %d\n", user_specified_pid);
    return len;
}

// proc 파일 시스템 연산 구조체 정의
static const struct proc_ops ancestor_proc_ops = {
    .proc_open = ancestor_open,
    .proc_read = seq_read,
    .proc_write = ancestor_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// 커널 모듈이 로드될 때 호출되는 함수
static int __init ancestor_init(void){
    // 파일 생성
    ancestor_entry = proc_create(PROC_NAME, 0666, NULL, &ancestor_proc_ops);

    // 파일 생성 실패 처리
    if(!ancestor_entry){
        pr_err("Failed to create /proc/ancestor\n");
        return -ENOMEM;
    }

    // 로그 출력
    pr_info("ancestor module loaded. /proc/ancestor created.\n");
    return 0;
}

// 커널 모듈이 언로드 될 때 호출되는 함수
static void __exit ancestor_exit(void){
    // 파일 삭제
    if(ancestor_entry){
        proc_remove(ancestor_entry);
    }

    // 로그 출력
    pr_info("ancestor module unloaded. /proc/ancestor removed.\n");
}

module_init(ancestor_init);
module_exit(ancestor_exit);