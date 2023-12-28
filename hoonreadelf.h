//심볼 이름과 주소를 저장하는 구조체
typedef struct ELF_Symbol{
    char name[50];
    unsigned long offset;
}ELF_Symbol;

//ELF_Symbol의 배열
typedef struct SymbolArr{
    ELF_Symbol *arr;
    int size;
} SymbolArr;

// dump_symbol 지정한 ELF 바이너리의 심볼 읽기
int dump_symbol(const char* filename, SymbolArr *sarr);

// sybol_lookup: name 인자로 지정한 심볼 오프셋 찾기
unsigned long long symbol_lookup(const char* name, SymbolArr* sarr);