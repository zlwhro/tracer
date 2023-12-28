#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include "hoonreadelf.h"
#include "hoondebug.h"

int restore_return = 0;
char fullpath[1024];
char seedpath[1024];
char preload[1024] ="LD_PRELOAD=";
char crash_dir[1024];
int crash_dir_len;

unsigned mut_idx;
unsigned mut_size;

unsigned iter;
unsigned crash_count =0;
unsigned interation = 0;

int prev_percent =0;


int do_fuzz(unsigned long snapshot_point, unsigned long restore_point, SymbolArr* vuln_symbols, SymbolArr* hook_symbols )
{
    pid_t pid = fork();
    if(pid == -1)
        puts("fork error");
    //fork를 실행하면 자식 프로세스는 0을 리턴한다.
    else if(pid == 0)
    {
        char *argv[] = {fullpath, seedpath, NULL};
        //부모 프로세스가 이 프로세스를 추적할 것임을 알린다.
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        getcwd(preload+11, sizeof(preload) -11);
        // 후킹 라이브러리 삽입
        strcat(preload, "/fuzzhook.so");

        
        const char * env[]= {preload, NULL};
        char *const *envp = (char *const *)env;

        //자식 프로세스의 표준출력, 표준 에러 무시
        int dev_null = open("/dev/null", O_RDWR);
        if(dev_null == -1)
            puts("????");
        dup2(dev_null, 1);
        dup2(dev_null, 2);
        //타겟 프로그램 실행
        execve(fullpath,argv, envp);
    }
    //부모 프로세스
    else
    {
        int status;
        unsigned long base_addr, retrun_addr, hook_base;
        struct  user_regs_struct saved_regs;
        struct  user_regs_struct mutation_regs;

        //ptrace로 추적중인 프로세스가 execve를 호출하면 sigtrap 발생 프로세스 일시 정지
        waitpid(pid, &status, 0);
        if(WIFEXITED(status))
        {
            printf("exited why?\n");
            return -1;
        }
        //메모리 매핑을 읽고 베이스 주소 구하기
        base_addr = get_base(pid, "hoonzip");
        //스냅샷 저장 지점
        breakpoint bp_snap = {snapshot_point + base_addr, 0, 0 };
        //스냅샷 포인트에 중단점 설정
        set_breakpoint(pid, &bp_snap);
       
        //중단점까지 실행
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);

        //스냅샷 포인트까지 실행하지 못하고 프로세스 종료
        if(WIFEXITED(status))
        {
            puts("child exited why?");
            puts("failed to run until snapshot point");
            if(WIFSIGNALED(status))
            {
                printf("fail to reach snapshot point signal %d\n",WTERMSIG(status));
            }
            return -1;
        }
        //sigtrap이 아닌 다른 시그널 발생 
        else if(!WIFSTOPPED(status) || WSTOPSIG(status) != 5)
        {
            puts("something wrong");
            return -1;
        }

        // rip 레지스터를 읽고 스냅샷 포인트까지 도착했는지 확인
        ptrace(PTRACE_GETREGS, pid, 0, &saved_regs);
        memcpy(&mutation_regs, &saved_regs, sizeof(mutation_regs));
        if(saved_regs.rip != bp_snap.addr+1)
        {
            puts("failed to reach snapshot point");
            return -1;
        }
        // 무사히 도착하면 중단점 해제
        dsiable_breakpoint(pid, &bp_snap);

        unsigned long file_idx =0, saved_file_idx=0, snapshot_saved = 0, fuzz_setup = 0, save_crash =0;
        unsigned long mutation_idx, mutation_size, crash_file;
 
        //스냅샷 포인트를 함수 이름으로 설정하면 자동으로 리턴 주소를 restore point에 추가
        //rsp 레지스터가 가리키는 주소를 읽는다. 그 위치에 리턴 주소가 저장되어 있다.
        if(restore_return)
        {
            retrun_addr = get_qword(pid, saved_regs.rsp);

            breakpoint bp_restore1 = {retrun_addr, 0, 0 };
            set_breakpoint(pid, &bp_restore1);
        }
        //직접 오프셋을 입력해서 restore point를 설정한 경우 restore point도 직접 입력한 주소로 설정
        else
        {
            breakpoint bp_restore1 = {restore_point + base_addr, 0, 0 };
            set_breakpoint(pid, &bp_restore1);
        }

        //exit@plt는 항상 restore point에 추가된다.
        unsigned long exit_addr = symbol_lookup("exit", vuln_symbols);
        breakpoint bp_restore2 = {exit_addr + base_addr, 0, 0 };
        set_breakpoint(pid, &bp_restore2);

        //후킹 라이브러리 베이스 주소 구하기
        hook_base = get_base(pid, "fuzzhook.so");

        //후킹 라이브러리에서 필요한 심볼의 오프셋을 읽는다. 아래 심볼들은 스냅샷 복구와 muation에 사용할 변수와 함수다.
        file_idx = symbol_lookup("file_idx", hook_symbols);
        saved_file_idx = symbol_lookup("saved_file_idx", hook_symbols);
        snapshot_saved = symbol_lookup("snapshot_saved", hook_symbols);
        fuzz_setup = symbol_lookup("fuzz_setup", hook_symbols);
        save_crash = symbol_lookup("save_crash", hook_symbols);
        mutation_idx = symbol_lookup("mutation_idx", hook_symbols);
        mutation_size = symbol_lookup("mutation_size", hook_symbols);
        crash_file = symbol_lookup("crash_file", hook_symbols);
        
        
        //fuzz_setup 주소 저장
        //fuzz_setup은 스냅샷을 복구하고(단 레지스터는 부모 프로세스가 ptrace로 복구해준다.) muation을 수행한다.
        mutation_regs.rip = hook_base+fuzz_setup;

        if(file_idx == 0 || saved_file_idx == 0 || snapshot_saved == 0 || fuzz_setup == 0 || save_crash == 0)
        {
            puts("fail read symbol");
            return -1;
        }

        // 파일 오프셋 저장
        // fread나 fseek를 실행하면 파일 오프셋이 변경된다. 파일 오프셋을 저장한다. 

        // 현재 파일 오프셋 읽기
        int snap_idx = get_dword(pid, hook_base+file_idx);

        // saved_file_idx에 저장
        set_dword(pid, hook_base + saved_file_idx, snap_idx);

        // snapshot_saved에 1 저장 스냅샷이 저장되었다는표시다.
        set_dword(pid, hook_base + snapshot_saved, 1);

        // mutation 설정
        set_dword(pid, hook_base + mutation_idx, mut_idx);
        set_dword(pid, hook_base + mutation_size, mut_size);

        //crash 파일을 저장할 위치 지정
        snprintf(crash_dir +crash_dir_len, sizeof(crash_dir), "%d.zip", crash_count);

        write_str(pid, hook_base+crash_file, crash_dir);

        // 프로세스 재실행        
        ptrace(PTRACE_CONT, pid, 0, 0);

        // 퍼징 시작
        while(iter < interation)
        {
            iter++;
            int precent = (iter*100) /interation;
            if(precent > prev_percent)
            {
                prev_percent = precent;
                char message[100];
                snprintf(message, sizeof(message), "\tprocess: %d%%\r", precent);
                write(1, message, 15);
            }
            waitpid(pid, &status, 0);
            struct user_regs_struct cur_regs;

            //ptrace로 추적 중인 프로세스는 SIGKILL 외 다른 시그널이 발생해도 정지하지 않는다.
            //정지한 이유를 알 수 없는 상황
            if(WIFEXITED(status))
            {
                puts("child exited why?");
                return -1;
            }
            // 프로세스가 일시 정지함
            // 소프트웨어 브레이크 포인트는 SIGTRAP(5)을 발생시키는 int 3 인스트럭션을 사용한다.
            // 시그널 번호가 5라면 중단점에 도착했다는 의미 
            // 그 외 다른 시그널은 프로세스가 잘못된 동작을 하여 SIGSEGV, SIGABRT 등이 발생했다는 의미
            else if(WIFSTOPPED(status))
            {
                // 충돌 발생 
                // 스냅샷 기능이 온전하지 않기 때문에 퍼징과정에서 충돌이 발생해도 실제 실행과정에서 충돌이 발생하지 않는 경우가 있다.
                if(WSTOPSIG(status) != 5)
                {

                    struct user_regs_struct crash_regs;
                    int ret = WSTOPSIG(status);

                    // save_crash 함수로 rip 주소 변경
                    // 충돌이 발생한 파일을 저장한다.
                    cur_regs.rip = hook_base + save_crash;
                    ptrace(PTRACE_SETREGS, pid, 0, &cur_regs);
                    ptrace(PTRACE_CONT,pid, 0, 0);

                    waitpid(pid, &status, 0);

                    //프로세스 종료
                    ptrace(PTRACE_KILL, pid, 0, 0);
                    printf("\nsignal %d crash saved %s\n",ret, crash_dir);
                    crash_count +=1;
                    return ret;
                }
            }

            //fuzz_setup 함수로 rip 레지스터 변경
            //mutation 과 파일 오프셋을 복구하고 해제되지 않은 힙을 정리한다.
            ptrace(PTRACE_SETREGS, pid, 0, &mutation_regs);
            ptrace(PTRACE_CONT,pid, 0, 0);

            waitpid(pid, &status, 0);

            if(WIFEXITED(status))
            {
                puts("child exited why?");
                return -1;
            }
            //fuzz_setup 함수는 mutation과 스냅샷 복구가 끝나면 SIGTRAP을 발생시키는 Int 3을 실행한다
            else if(WIFSTOPPED(status))
            {
                // 스냅샷 시점으로 레지스터 복구
                if(WSTOPSIG(status) == 5)
                {
                    ptrace(PTRACE_SETREGS, pid, 0, &saved_regs);
                    ptrace(PTRACE_CONT, pid, 0 ,0);    
                }
                // fuzz_setup 실행중 에러 발생
                else{
                    puts("error while setup");
                    printf("sig %d\n",WSTOPSIG(status));

                    return -1;
                }
            }
        }
        // 지정한 반복 횟수 초과
        puts("done");
        ptrace(PTRACE_KILL, pid, 0, 0);
        return 0;
    }
}

int main(int argc, char **argv)
{
    char path[256];

    //심볼 주소르 저장할 구조체
    SymbolArr vuln_symbols;
    SymbolArr hook_symbols;

    unsigned long snapshot_point = 0;
    unsigned long restore_point = 0;

    struct stat hookstat;

    //후킹 라이브러리가 같은 폴더에 있어야 한다.
    if(stat("fuzzhook.so", &hookstat) !=0){
        puts("can\'t find fuzzhook.so");
        return 0;
    }

    //후킹 라이브러리의 심볼 주소 덤프
    dump_symbol("fuzzhook.so", &hook_symbols);

    int select;

    puts("Hi I'm tracer a dumb fuzzer");
    puts("where is vulnerable binary?");

    //테스트할 바이너리 파일 입력
    while(1)
    {
        struct stat vuln_stat;
        printf("path: ");
        scanf("%999s",path);
        int ret =stat(path, &vuln_stat);
        if(ret == 0)
        {
            if(vuln_stat.st_mode & __S_IFREG)
                break;
        }
        printf("please check file name. can\'t open file name: %s\n", path);
    }
    if(path[0] != '/')
    {
        getcwd(fullpath, sizeof(fullpath));
        strcat(fullpath, "/");
        strcat(fullpath, path);
        puts(fullpath);
    }
    else
        strcpy(fullpath, path);
    dump_symbol(fullpath, &vuln_symbols);
    
    //seed로 사용할 zip 파일 입력
    puts("================================================================");
    puts("where is seed file?");
    while(1)
    {
        struct stat vuln_stat;
        printf("path: ");
        scanf("%999s",path);
        int ret =stat(path, &vuln_stat);
        if(ret == 0)
        {
            if(vuln_stat.st_mode & __S_IFREG)
                break;
        }
        printf("please check file name. can\'t open file name: %s\n", path);
    }

    if(path[0] != '/')
    {
        getcwd(seedpath, sizeof(seedpath));
        strcat(seedpath, "/");
        strcat(seedpath, path);
        puts(seedpath);
    }
    else
        strcpy(seedpath, path);

    // snapshot point로 설정할 함수 혹은 오프셋 지정
    // 1. 함수를 스냅샷 포인트로 지정 함수 목록을 3을 입력하면 확인 할 수 있다. restore point는 자동으로 함수의 리턴 주소로 설정된다.
    // 2. 스냅샷 포인트로 설정할 오프셋 직접입력 이 경우 restore point도 직접 입력해야 한다.
    // 3. 3을 입력하면 함수 목록과 오프셋을 확인 할 수 있다.
    while(snapshot_point == 0)
    {
        puts("================================================================");
        puts("set snapshot point");
        puts("1. set snopshot point by function name");
        puts("2. set snopshot point by offset");
        puts("3. list symbols");
        printf("select :");
        scanf("%d",&select);
        switch (select)
        {
            case 1:
            {
                char func[100];
                printf("function name: ");
                scanf("%s", func);
                snapshot_point =symbol_lookup(func, &vuln_symbols);
                if(snapshot_point == 0)
                    printf("can\'t find function name %s", func);
                else
                {
                    printf("set snapshot offset %lx\n", snapshot_point);
                    printf("restore return %s\n",func);
                    restore_return = 1;
                }
                break;
            }
            case 2:
            {
                printf("offset: ");
                scanf("%lx", &snapshot_point);
                printf("set snapshot offset %lx\n", snapshot_point);
                break;
            }
            case 3:
            {
                puts("================================================================");
                puts("function list");
                for(int i=0;i<vuln_symbols.size;++i)
                    printf("offset: %lx name: %s\n",vuln_symbols.arr[i].offset, vuln_symbols.arr[i].name);
                
                break;
            }
            default:
            break;
        }
    }
    //함수 이름으로 스냅샷 포인트를 설정하지 않았다면 restore point도 직접 설정
    if(restore_return == 0)
    {
        puts("================================================================");
        puts("set restore point");
        printf("offset :");
        scanf("%lx",&restore_point);
    }
    //mutation 설정
    puts("================================================================");
   
    // 입력 데이터에서 mutation을 진행할 위치를 설정
    // ZIP_Decompess만 테스트하고 싶다면 헤더를 제외하고 진짜 압축 데이터가 들어있는 위치를 입력한다.
    puts("set mutation");
    printf("mutation_idx: ");
    scanf("%d",&mut_idx);

    // mutation 범위 지정
    // mut_idx ~ (mut_idx+mut_size) 범위에 있는 바이트 중 1퍼센트가 랜덤으로 변경
    printf("mutation_size: ");
    scanf("%d",&mut_size);

    // 반복 횟수 설정 
    puts("================================================================");
    puts("how many iteration do you want?");
    printf("iter: ");
    scanf("%d", &interation);

    // 충돌이 발생한 zip 파일을 저장할 위치
    puts("================================================================");
    puts("save path");
    printf("path: ");
    scanf("%999s",path);
    if(path[0] != '/')
    {
        getcwd(crash_dir, sizeof(crash_dir));
        strcat(crash_dir, "/");
        strcat(crash_dir, path);
        strcat(crash_dir, "/crash");
    }
    else
    {
        strcpy(crash_dir, path);
        strcat(crash_dir, "/crash");
    }
    puts(crash_dir);
    crash_dir_len = strlen(crash_dir);

    // 퍼징 시작
    puts("================================================================");
    puts("setup complete");
    puts("start fuzzing");

    
    while(iter < interation )
    {
        //ret이 -1 이면 스냅샷 포인트까지 실행하지 못하거나 스냅샷 복구중 오류가 발생했다는 의미
        int ret = do_fuzz(snapshot_point, restore_point, &vuln_symbols, &hook_symbols);
        if(ret == -1)
        {
            puts("something wrong...");
            break;
        }
    }
    return 0;
}