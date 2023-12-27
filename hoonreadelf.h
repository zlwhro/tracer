//read Null terminated string from file
typedef struct ELF_Symbol{
    char name[50];
    unsigned long offset;
}ELF_Symbol;

typedef struct SymbolArr{
    ELF_Symbol *arr;
    int size;
} SymbolArr;

int dump_symbol(const char* filename, SymbolArr *sarr);
unsigned long long symbol_lookup(const char* name, SymbolArr* sarr);