#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdlib.h>
#include<time.h>

// SIGTRAP 발생
#define DebugBreak() asm("int $3")

// 후킹한 함수의 원래 주소를 저장할 함수 포인터
FILE *(*real_fopen)(const char *pathname, const char *mode) = NULL;
int (*real_fclose)(FILE *f) = NULL;
int (*real_fseek)(FILE *f, long offset, int whence) = NULL;
size_t (*real_fread)(void *ptr, size_t size, size_t n, FILE *stream) = NULL;
size_t (*real_fwrite)(const void *ptr, size_t size, size_t n, FILE *stream) = NULL;
long (*real_ftell)(FILE *f) = NULL;
void *(*real_malloc)(size_t size) = NULL;
void (*real_free)(void *ptr) = NULL;
int (*real_mkdir)(const char *pathname, mode_t mode) = NULL;


char *original = NULL;
char *mutated = NULL;
int file_size;
int snapshot_saved = 0;
int file_idx = 0;
int saved_file_idx;

int mutation_idx = 70;
int mutation_size = 4983833;
float mutation_ratio = 0.01;

int seed_set = 0;

void* heap_list[100];
int heap_idx=0;

char crash_file[1000];

FILE* fopen(const char *pathname, const char *mode)
{
    //함수 포인터에 원래 함수 주소 저장
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
        real_fclose = dlsym(RTLD_NEXT, "fclose");
        real_fread = dlsym(RTLD_NEXT, "fread");
        real_fwrite = dlsym(RTLD_NEXT, "fwrite");
        real_fseek = dlsym(RTLD_NEXT, "fseek");
        real_ftell = dlsym(RTLD_NEXT, "ftell");
        real_malloc = dlsym(RTLD_NEXT, "malloc");
        real_free = dlsym(RTLD_NEXT, "free");
    }

    FILE* fake = (FILE *)0x1111;
    //파일 쓰기는 하지 않는다.
    if(mode[0] == 'w')
        return fake;

    if(original != NULL)
    {
        file_idx = 0;
        return fake;
    }

    FILE *fp = real_fopen(pathname, mode);
    //파일 크기 확인
    real_fseek(fp, 0, SEEK_END);
    file_size = real_ftell(fp);
    //파일 전체를 메모리에 쓰고 이후 fread 요청은 메모리에서 처리한다.
    real_fseek(fp, 0, SEEK_SET);
    
    original = real_malloc(file_size);
    mutated = real_malloc(file_size);
    // 원본 데이터를 original에 쓰고 mutation에도 같은 내영 복사
    real_fread(original, 1, file_size, fp);
    memcpy(mutated, original, file_size);
    //파일을 읽고 곧바로 파일을 닫는다.
    real_fclose(fp);
    return fake;
}

//do nothing
int fclose(FILE *fp)
{
    return 0;
}

//파일 오프셋은 전역변수 file_idx에 저장
//fseek 호출은 file_idx를 변경하도록 바꾼다.
int fseek(FILE *stream, long offset, int origin)
{
    if(!real_fseek)
        real_fseek = dlsym(RTLD_NEXT, "fseek");

    if(origin==SEEK_SET)
        file_idx =  offset;
    else if(origin == SEEK_CUR)
        file_idx += offset;
    else
        file_idx = file_size+offset;
    return 0;
}
//파일 쓰기는 하지 않는다.
size_t fwrite(const void *ptr, size_t size, size_t n, FILE *stream)
{
    //do nothing
    return 1;
}
//미리 메모리에 복사해둔 데이터를 읽는다.
//미리 메모리에 올려두면 파일 쓰기 없이 메모리만 수정해서 mutation을 수행할 수 있다.
size_t fread(void *buffer, size_t size, size_t count, FILE* stream)
{
    size_t readsize = size * count;
    if(readsize > file_size - file_idx)
        readsize = file_size - file_idx;

    memcpy(buffer, mutated+file_idx, readsize);
    file_idx += readsize;
    return readsize/size;
}

long ftell(FILE* fp)
{
    return file_idx;
}

void* malloc(size_t size)
{
    if(!real_malloc)
        real_malloc = dlsym(RTLD_NEXT, "malloc");

    //스냅샷을 저장하기 전까지는 기존 malloc과 같이 동작
    if(!snapshot_saved)
    {
        return real_malloc(size);
    }
    else
    {
        //스냅샷을 저장한 이후로 할당된 힙 기억하기
        void *chunk = real_malloc(size);
        heap_list[heap_idx++] = chunk;
        return chunk;
    }
}


void free(void *ptr)
{
    if(!real_free)
        real_free = dlsym(RTLD_NEXT, "free");

    //힙 리스트에서 지운다. 
    if(snapshot_saved)
    {
        
        for(int i=0;i<heap_idx;++i)
            if(heap_list[i] == ptr)
            {
                
                heap_list[i] = NULL;
                break;
            }
    }

    real_free(ptr);
}

// 디렉토리 생성은 하지않는다.
int mkdir(const char *pathname, mode_t mode){
    return 0;
}

//스냅샷 복원
//레지스터 복구는 부모 프로세스에서 ptrace로 수행
void snapshot_restore()
{
  //스냅샷을 복구할때 남아있는 힙 한번에 정리
    
    for(int i=0; i<heap_idx; ++i)
        if(heap_list[i] != NULL)
        {
            //fprintf(stderr,"free %lx %p\n",*(long *)(heap_list[i]-8), heap_list[i] );
            real_free(heap_list[i]);
            
            heap_list[i]= NULL;
            //fprintf(stderr,"free %p\n",heap_list[i]);
        }
    heap_idx = 0;
    //파일 오프셋 복원
    file_idx = saved_file_idx;
}

// 지정한 범위의 바이트 중 1 퍼센트를 랜덤으로 변경
void mutation()
{
    int msiz = mutation_size;
    if(msiz == 0)
    {
        msiz = file_size - mutation_idx;
        fprintf(stderr,"msiz %d\n",msiz);
    }

    memcpy(&mutated[mutation_idx], &original[mutation_idx], msiz);
    int mutation_time = (int)(mutation_ratio * msiz);

    // 현재 시간을 시드로 설정
    if(!seed_set)
    {
        srand(time(NULL));
        seed_set = 1;
    }

    //위치과 범위를 지정해서 mutation 수행
    for(int i=0; i<mutation_time; ++i)
    {
        int select = rand() % msiz + mutation_idx;
        int value = rand() & 0xff;
        mutated[select] = (char)value;
    }
}

// 스냅샷 복구 & mutataion 
void fuzz_setup()
{
    snapshot_restore();
    mutation();
    // SIGTRAP을 발생시켜서 부모 프로세스에게 작업이 끝났음을 알린다.
    DebugBreak();
}

// 충돌이 발생한 ZIP 파일 저장
void save_crash()
{
    FILE* crash = real_fopen(crash_file, "wb");
    real_fwrite(mutated,1, file_size, crash);
    real_fclose(crash);

    DebugBreak();
}
