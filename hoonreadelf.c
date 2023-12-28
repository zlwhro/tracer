#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include "hoonreadelf.h"

//hoonreadelf.c 심볼 주소 찾기

//파일에서 NULL terminated string 읽기
int freadstr(FILE *fp, long offset, char *buf, int maxsize)
{
    char c;
    int idx = 0;
    fseek(fp, offset, SEEK_SET);
    do{
        c = fgetc(fp);
        buf[idx++] = c;

    }while (c != '\0');

    return idx-1;
}
// ELF 파일에서 심볼 읽기
int dump_symbol(const char* filename, SymbolArr *sarr)
{
    FILE *hook = fopen(filename,"rb");   
    Elf64_Sym elf_symbol;

    char *shstr, *strtbl, *dymstr;
    Elf64_Sym *symtbl, *dymsym;
    Elf64_Rela *rela_plt;
    unsigned long plt_sec;
    
    char *data = NULL;
    Elf64_Ehdr *elf_header;
    Elf64_Shdr *section_header;

    int sym_num, dymsym_num, rela_plt_num;
    unsigned long filesize;

    char temp[100];

    //파일 전체 읽기

    //파일 크기 확인
    fseek(hook, 0, SEEK_END);
    filesize = ftell(hook);
    //파일 크기만큼 메모리 할당하고 파일 전체 읽기
    fseek(hook, 0, SEEK_SET);
    data = malloc(filesize+1);
    fread(data, filesize, 1, hook);
    fclose(hook);

    //ELF 헤더를 읽는다.
    elf_header = (Elf64_Ehdr *)data;
    
    //섹션 헤더 테이블 오프셋 확인
    //해당 테이블은 모든 섹션 헤더의 오프셋이 저장되어 있다.
    section_header = (Elf64_Shdr*)(data + elf_header->e_shoff);

    //shstrtab 오프셋 확인 섹션의 이름이 저장되어 있다.
    for(int i=0;i<elf_header->e_shnum;++i)
    {
        if(section_header[i].sh_type == SHT_STRTAB)
        {
            strcpy(temp, data + section_header[i].sh_offset + section_header[i].sh_name);
            if(strcmp(temp, ".shstrtab") == 0)
                shstr = data + section_header[i].sh_offset;
        }
    }

    //각 섹션의 오프셋 확인
    // 필요한 섹션은 .strtab, .dynstr, .dynsym, symtab, .rela.plt, .plt.sec
    for(int i=0;i<elf_header->e_shnum;++i)
    {
        strcpy(temp, shstr + section_header[i].sh_name);

        if(strcmp(temp, ".strtab") == 0)
            strtbl = data + section_header[i].sh_offset;
        else if(strcmp(temp, ".dynstr") == 0)
            dymstr= data + section_header[i].sh_offset;
        else if(strcmp(temp, ".dynsym") == 0)
        {
            dymsym = (Elf64_Sym * )(data + section_header[i].sh_offset);
            dymsym_num = section_header[i].sh_size / section_header[i].sh_entsize;
        }
        else if(strcmp(temp, ".symtab") == 0)
        {
            symtbl = (Elf64_Sym * )(data + section_header[i].sh_offset);
            sym_num = section_header[i].sh_size / section_header[i].sh_entsize;
        }
        else if(strcmp(temp, ".rela.plt") == 0)
        {
            rela_plt = (Elf64_Rela * )(data + section_header[i].sh_offset);
            rela_plt_num = section_header[i].sh_size / section_header[i].sh_entsize;
        }
        else if(strcmp(temp, ".plt.sec") == 0)
            plt_sec = section_header[i].sh_offset;
    }
    //심볼 테이블 읽기
    sarr->arr = malloc(sizeof(ELF_Symbol) * sym_num);
    sarr->size = 0;
    for(int i=0;i<sym_num;++i)
    {
        long val = symtbl[i].st_value; // 심볼의 주소
        //스트링 테이블에서 이름 확인
        if(val != 0)
        {
            //주소와 이름 저장
            int cur = sarr->size;
            sarr->arr[cur].offset = val;
            //st_name은 .strtab에서 심볼 이름이 저장된 오프셋을 나타낸다.
            strcpy(sarr->arr[cur].name, strtbl + symtbl[i].st_name);
            sarr->size += 1;
        }
    }
    // rela.plt 읽기
    // 실행시점에 주소가 정해지는 심볼들의 relocation 정보가 저장되어 있다.
    // 라이브러리 함수들의 plt 엔트리 주소를 저장하기 위해서다. 
    for(int i=0;i<rela_plt_num;++i)
    {
        long name = (rela_plt[i].r_info) >> 32;
        long offset = plt_sec + 0x10*i;
        int cur = sarr->size;
        sarr->arr[cur].offset = offset;
        strcpy(sarr->arr[cur].name, dymstr + dymsym[name].st_name);
        sarr->size += 1;
    }
    free(data);
}

//심볼 주소 확인
unsigned long long symbol_lookup(const char* name, SymbolArr* sarr)
{   
    unsigned long long ret =0;
    for(int i=0; i < sarr->size; ++i)
        if(strcmp(name, sarr->arr[i].name) ==0)
        {
            ret = sarr->arr[i].offset;
            break;
        }
    return ret;
}