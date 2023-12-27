#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <string.h>
#include <stdio.h>
#include "hoondebug.h"

//자식 프로세스의 베이스 주소 구하기
//pid: 자식 프로세스의 프로세스 id
//target: 자식 프로세스에서 execve로 실행한 바이너리 파일 이름
unsigned long long get_base(pid_t pid, char * target)
{
    char proc_path[1000];
    char memory_map[1000];
    unsigned long long address;

    snprintf(proc_path, sizeof(proc_path), "/proc/%d/maps",pid);
    
    FILE *proc_file = fopen(proc_path, "r");
    fgets(memory_map, sizeof(memory_map), proc_file);
    
    //베이스 주소 읽기
    //파일 이름에 target이 포함되면 루프 종료
    while(strstr(memory_map, target) == 0)
    {
        fgets(memory_map, sizeof(memory_map), proc_file);
        //puts(memory_map);
    }
    
    fclose(proc_file);
    for(int i=0;i< 26;++i)
    {
        if(memory_map[i] == '-')
        {
            memory_map[i] = '\0';
            break;
        }
    }
    sscanf(memory_map, "%llx", &address);
    return address;
}



// 중단점 설정
void set_breakpoint(pid_t pid, breakpoint *bp)
{

    long code = 0;
    //중단점을 설정할 주소의 원래 코드 저장
    code = ptrace(PTRACE_PEEKDATA, pid, bp->addr, NULL);
    bp->save =  code;
    //코드의 첫 바이트를 int 3(0xcc)로 바꾼다.
    long code_with_int3 = ((code & ~0xffl) | 0xccl);
    //printf("set breakpoint at 0x%llx\n",bp->addr);
    ptrace(PTRACE_POKEDATA, pid, bp->addr, code_with_int3);
    bp->enabled = 1;
}

void dsiable_breakpoint(pid_t pid, breakpoint *bp)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if(regs.rip == bp->addr+1)
    {
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);
    }
    ptrace(PTRACE_POKEDATA, pid, bp->addr, bp->save);
    bp->enabled = 0;
}

//중단점에서 다시 시작
void bp_continue(pid_t pid, breakpoint *bp)
{
    struct user_regs_struct regs;
    int status;

    //인스트럭션 원래대로 되돌리기
    ptrace(PTRACE_POKEDATA, pid, bp->addr, bp->save);

    //rip에서 1 빼기
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    regs.rip--;
    ptrace(PTRACE_SETREGS, pid, 0, &regs);

    //인스트럭션 1개 실행
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    waitpid(pid, &status, 0);

    //다시 int 3 쓰기
    ptrace(PTRACE_POKEDATA, pid, bp->addr, (bp->save | 0xccl));
    ptrace(PTRACE_CONT,pid, 0, 0);
    //puts("continue");
}

//메모리 읽기와 쓰기
void set_dword(pid_t pid, unsigned long long addr, unsigned value)
{
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    data &= (~0xffffffffl);
    data |= value;
    ptrace(PTRACE_POKEDATA, pid, addr, data);
}

void set_qword(pid_t pid, unsigned long long addr, unsigned long long value)
{
    ptrace(PTRACE_POKEDATA, pid, addr, value);
}

long get_qword(pid_t pid, unsigned long long addr)
{
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    return data;
}

int get_dword(pid_t pid, unsigned long long addr)
{
    long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    return (int)(data & 0xffffffff);
}

//스택 읽기
long read_stack(pid_t pid, unsigned long long offset)
{
    long rsp =  ptrace(PTRACE_PEEKUSER, pid, RSP, 0);
    //printf("rsp: %lx\n", rsp);
    return get_qword(pid, rsp+offset);
}

//스택 읽기
void write_stack(pid_t pid, unsigned long long offset, long value)
{
    long rsp =  ptrace(PTRACE_PEEKUSER, pid, RSP, 0);
    //printf("rsp: %lx\n", rsp);
    set_qword(pid, rsp+offset, value);
}

//문자열 쓰기
void write_str(pid_t pid, unsigned long long addr, const char* str)
{
    int size = strlen(str) + 1;
    unsigned long long cur = addr;
    long *p = (long *)str;
    while(cur < addr+size)
    {
        set_qword(pid, cur, *p);
        cur +=8;
        p +=1 ;
    }
}