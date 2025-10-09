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

// 커널 모듈의 라이센스와 작성자 정보
MODULE_LICENSE("GPL");
MODULE_AUTHOR("JEON Hyunwoo");

// proc 파일 시스템 파일 이름
#define PROC_NAME "proc_analyzer"
// 분석 가능한 최대 프로세스 수 상한
#define MAX_PROCESSES 1024

// 사용자가 입력한 PID를 저장하는 변수 (기본값 1)
static pid_t user_specified_pid = 1;

// CFS runqueue에 있는 프로세스 정보를 저장하는 구조체
struct process_info {
    pid_t process_id; // id
    char process_name[TASK_COMM_LEN]; // 프로세스 이름
    unsigned long long virtual_runtime; // virtual runtime
    int cpu_number; // CPU 번호
};

// 특정 프로세스가 다른 프로세스의 자손인지 확인하는 함수
static bool is_descendant(struct task_struct *task_to_check, struct task_struct *ancestor_task){
    // 확인할 프로세스부터 시작
    struct task_struct *current_parent = task_to_check;

    // 부모를 따라 올라가며 조상 프로세스를 찾는 반복문
    while(current_parent && current_parent->pid != 0){
        if(current_parent == ancestor_task){ // 만약 현재 확인 중인 프로세스가 찾는 조상과 일치한 경우
            return true;
        }
        // 한 단계 위 프로세스로 이동
        current_parent = current_parent->real_parent;
    }

    // 조상을 찾지 못한 경우
    return false;
}

// 프로세스가 현재 CFS runqueue에 있는지 확인하는 함수
static bool is_on_cfs_rq(struct task_struct *task_to_check){
    // 프로세스 스케줄링 정책
    int pol = READ_ONCE(task_to_check -> policy);
    // cfs 스케줄러를 사용하는 정책인지 확인
    if(pol != SCHED_NORMAL && pol != SCHED_BATCH && pol != SCHED_IDLE){
        return false; // 다른 스케줄러 정책 사용
    }

    // cfs runqueue에 있는지 확인
    return READ_ONCE(task_to_check -> on_rq) > 0;
}

// virtual runtime을 기준으로 두 프로세스를 비교하는 함수
static int compare_vruntime(const void *first_process, const void *second_process){
    // 프로세스 정보
    const struct process_info *first_process_info = (const struct process_info*)first_process;
    const struct process_info *second_process_info = (const struct process_info *)second_process;

    // 두 프로세스의 virtual runtime 비교
    if(first_process_info -> virtual_runtime < second_process_info -> virtual_runtime){
        return -1;
    }else if (first_process_info -> virtual_runtime > second_process_info -> virtual_runtime){
        return 1;
    }else{
        return 0;
    }
}

// 프로세스 파일을 읽을 때 호출되는 함수
static int proc_analyzer_show(struct seq_file *sequence_file, void *unused){
    struct task_struct *current_task, *target_task; // 프로세스 정보를 담은 구조체
    struct pid *pid_descriptor; // PID 구조체
    struct process_info *cfs_process_array; // CFS runqueue의 프로세스 정보를 저장할 배열
    int total_process_count = 0, array_index, cpu_index; // 카운터 및 인덱스
    int total_cpu_count = num_online_cpus(); // 시스템의 온라인 CPU 개수
    int *processes_per_cpu; // 각 CPU 별 프로세스 개수를 저장할 배열

    // 프로세스 정보를 저장할 메모리 동적 할당
    cfs_process_array = kmalloc(MAX_PROCESSES * sizeof(struct process_info), GFP_KERNEL);
    if(!cfs_process_array){ // 메모리 할당에 실패할 경우 처리
        seq_printf(sequence_file, "ERROR: Memory allocation failed\n");
        return 0;
    }

    // CPU 별 프로세스 개수를 저장할 배열 할당
    processes_per_cpu = kzalloc(total_cpu_count * sizeof(int), GFP_KERNEL);
    if(!processes_per_cpu){ // 메모리 할당 실패 처리
        kfree(cfs_process_array);
        seq_printf(sequence_file, "ERROR: Memory allocation failed\n");
        return 0;
    }

    // 기본 정보 출력
    seq_printf(sequence_file, "ID: 2024148005\n");
    seq_printf(sequence_file, "Name: Jeon, Hyunwoo\n");
    seq_printf(sequence_file, "PID: %d\n", user_specified_pid);
    seq_printf(sequence_file, "----------------------------------------\n");

    // 입력한 PID에 해당하는 pid 구조체 찾기
    pid_descriptor = find_get_pid(user_specified_pid);
    if(!pid_descriptor){ // pid를 찾지 못한 경우 처리
        seq_printf(sequence_file, "ERROR: PID not found\n");
        // 할당한 메모리 해제
        kfree(cfs_process_array);
        kfree(processes_per_cpu);
        return 0;
    }

    // pid 구조체로부터 실제 프로세스 정보를 가져옴
    target_task = pid_task(pid_descriptor, PIDTYPE_PID);
    if(!target_task){ // 가져오지 못한 경우
        put_pid(pid_descriptor); // pid 참조 카운트 감소
        seq_printf(sequence_file, "ERROR: Task for PID is not found\n");
        // 할당한 메모리 해제
        kfree(cfs_process_array);
        kfree(processes_per_cpu);
        return 0;
    }

    // RCU 읽기 잠금
    rcu_read_lock();

    // 시스템의 모든 프로세스를 순회
    for_each_process(current_task){
        // 현재 프로세스가 목표 프로세스 자신이거나 그 자손인지 확인
        if(current_task == target_task || is_descendant(current_task, target_task)){
            // CFS runqueue에 있는지 확인
            if(is_on_cfs_rq(current_task)){
                // 오버플로우 방지
                if(total_process_count < MAX_PROCESSES){
                    // 프로세스 id 저장
                    cfs_process_array[total_process_count].process_id = current_task->pid;
                    // 프로세스 이름 복사
                    strncpy(cfs_process_array[total_process_count].process_name, current_task -> comm, TASK_COMM_LEN); // strncpy를 사용하여 지정된 길이만큼 문자열 복사
                    // 문자열 끝에 NULL 문자 명시적 추가
                    cfs_process_array[total_process_count].process_name[TASK_COMM_LEN - 1] = '\0';
                    // virtual runtime 값 저장
                    cfs_process_array[total_process_count].virtual_runtime = current_task -> se.vruntime;
                    // 프로세스가 현재 할당된 CPU 번호 저장
                    cfs_process_array[total_process_count].cpu_number = task_cpu(current_task);
                    // 찾은 프로세스 개수 증가
                    total_process_count++;
                }
            }
        }
    }

    // RCU 읽기 잠금 해제
    rcu_read_unlock();

    // pid 참조 카운트 감소
    put_pid(pid_descriptor);
    // 수집한 프로세스를 virtual runtime 기준으로 오름차순 정렬
    sort(cfs_process_array, total_process_count, sizeof(struct process_info), compare_vruntime, NULL);

    // 각 CPU 별로 프로세스 개수를 계산
    for(array_index = 0; array_index < total_process_count; array_index++){
        // 프로세스의 CPU 번호가 유효한지 확인
        if(cfs_process_array[array_index].cpu_number < total_cpu_count){
            // 프로세스 카운트 증가
            processes_per_cpu[cfs_process_array[array_index].cpu_number]++;
        }
    }

    // 프로세스 정부 출력
    for(cpu_index = 0; cpu_index < total_cpu_count; cpu_index++){
        // 프로세스가 있는 경우에만 출력
        if(processes_per_cpu[cpu_index] > 0){
            seq_printf(sequence_file, "[CPU #%d] Running processes: %d\n", cpu_index, processes_per_cpu[cpu_index]);
            for(array_index = 0; array_index < total_process_count; array_index++){
                if(cfs_process_array[array_index].cpu_number == cpu_index){
                    seq_printf(sequence_file, "[%d] %s %llu\n", cfs_process_array[array_index].process_id, cfs_process_array[array_index].process_name, cfs_process_array[array_index].virtual_runtime);
                }
            }
            seq_printf(sequence_file, "----------------------------------------\n");
        }
    }

    // 메모리 할당 해제
    kfree(cfs_process_array);
    kfree(processes_per_cpu);

    return 0;
}

// 파일을 열 때 호출되는 함수
static int proc_analyzer_open(struct inode *inode_ptr, struct file *file_ptr){
    return single_open(file_ptr, proc_analyzer_show, NULL); // proc_analyzer_show 함수를 파일 생성 함수로 등록
}

// 파일을 작성할 때 사용하는 함수
static ssize_t proc_analyzer_write(struct file *file_ptr, const char __user *user_buffer, size_t buffer_size, loff_t *file_offset){
    // 사용자 입력을 저장할 변수
    char input_buffer[32];
    // 문자열을 정수로 변환한 결과
    int conversion_result;
    // 변환된 pid 값을 저장할 변수
    pid_t received_pid;


    // 입력 크기를 확인
    if(buffer_size >= sizeof(input_buffer)){
        return -EINVAL;
    }

    // 사용자 공간에서 커널 공간으로 데이터 복사
    if(copy_from_user(input_buffer, user_buffer, buffer_size)){
        return -EFAULT;
    }

    // 문자열 끝에 NULL 문자를 추가
    input_buffer[buffer_size] = '\0';

    // 문자열을 정수로 변환
    conversion_result = kstrtoint(input_buffer, 10, &received_pid);
    // 변환 실패 케이스 처리
    if(conversion_result){
        return conversion_result;
    }

    // pid가 올바른 값인지 검사
    if(received_pid <= 0){
        return -EINVAL;
    }

    // 전역 변수 업데이트
    user_specified_pid = received_pid;
    // 로그에 기록
    pr_info("proc_analyzer: PID set to %d\n", user_specified_pid);

    return buffer_size;
}

// proc 파일 시스템 연산 구조체
static const struct proc_ops proc_analyzer_proc_ops = {
    .proc_open = proc_analyzer_open, // 파일 열기
    .proc_read = seq_read, // 파일 읽기
    .proc_write = proc_analyzer_write, // 파일 쓰기
    .proc_lseek = seq_lseek, // 파일 탐색
    .proc_release = single_release, // 파일 닫기
};

// 모듈을 로드할 때 초기화하는 함수
static int __init proc_analyzer_init(void){
    // /proc/proc_analyzer 파일 생성
    if(!proc_create(PROC_NAME, 0666, NULL, &proc_analyzer_proc_ops)){ // 모든 사용자 접근이 가능하도록 0666 권한 부여
        pr_err("Falied to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    // 모듈 로드에 성공 메시지
    pr_info("proc_analyzer module loaded. /proc/%s created.\n", PROC_NAME);

    return 0;
}

// 모듈이 삭제 될 때 실행되는 함수
static void __exit proc_analyzer_exit(void){
    // 파일 삭제
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("proc_analyzer module unloaded. /proc/%s removed.\n", PROC_NAME);
}

module_init(proc_analyzer_init);
module_exit(proc_analyzer_exit);