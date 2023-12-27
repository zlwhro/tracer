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

    //read all
    fseek(hook, 0, SEEK_END);
    filesize = ftell(hook);
    fseek(hook, 0, SEEK_SET);
    data = malloc(filesize+1);
    fread(data, filesize, 1, hook);
    fclose(hook);

    elf_header = (Elf64_Ehdr *)data;
    
    //section header table
    section_header = (Elf64_Shdr*)(data + elf_header->e_shoff);

    //shstrtab 오프셋 확인
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
        long val = symtbl[i].st_value;
        char info = symtbl[i].st_info;
        //심볼을 읽고 스트링 테이블에서 이름 확인
        if(val != 0)
        {
            //주소와 이름 저장
            int cur = sarr->size;
            sarr->arr[cur].offset = val;
            strcpy(sarr->arr[cur].name, strtbl + symtbl[i].st_name);
            sarr->size += 1;
        }
    }
    //plt 읽기 
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