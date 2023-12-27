#include <sys/types.h>

typedef struct breakpoint{
    unsigned long long addr; //중단점 주소
    unsigned long save; //원래 인스트럭션
    int enabled; //중단점 활성화
}breakpoint;

unsigned long long get_base(pid_t pid, char * target);
//중단점 설정
void set_breakpoint(pid_t pid, breakpoint *bp);
//중단점 해제
void dsiable_breakpoint(pid_t pid, breakpoint *bp);
//중단점에서 다시 시작
void bp_continue(pid_t pid, breakpoint *bp);
//메모리 읽기와 쓰기
void set_dword(pid_t pid, unsigned long long addr, unsigned value);
void set_qword(pid_t pid, unsigned long long addr, unsigned long long value);
long get_qword(pid_t pid, unsigned long long addr);
int get_dword(pid_t pid, unsigned long long addr);
//스택 읽기, 쓰기
long read_stack(pid_t pid, unsigned long long offset);
void write_stack(pid_t pid, unsigned long long offset, long value);

void write_str(pid_t pid, unsigned long long offset, const char* str);