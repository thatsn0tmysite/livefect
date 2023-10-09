#include <stdio.h>
#include <sys/types.h>
#include "match_t.h"
#include "export_t.h"

#ifndef H_LIVEFECT_UTILS
#define H_LIVEFECT_UTILS

#if defined(__LP64__)
    #define ElfW(type) Elf64_ ## type    
#else
    #define ElfW(type) Elf32_ ## type
#endif

/*Typedefs*/
typedef struct maps_entry {
    void* start;
    void* end;
    char flags[4];
    unsigned long long file_offset;
    uint dev_major;
    uint dev_minor;
    uint inode;
    char path[513];
    struct maps_entry * next;
} maps_entry_t;

typedef struct args_t {
    pid_t arg_pid;                                  //pid 
    char* arg_payload_path;                         //path to file containing payload
    bool arg_list_exports;                          //only list exports
    bool arg_list_maps;                             //only list maps
    bool arg_show_usage;                            //show help
    bool arg_force_disk;                            //force lookup of exported symbols from disk
    bool arg_skip_root;                             //skip root checks
    bool arg_inject_all;                            //inject payload into ALL matching memory areas 
    int arg_verbosity;                              //verbosity level
    int arg_disasm;                                 //instructions to disassemble
    int arg_disasm_bytes;                           //bytes to pass to disassemble
    void* arg_raddr;                                //remote address to write at in case of raw option
    char arg_perms[4];                              //permissions to look for
    bool arg_data_only;                             //only show data symbols
    bool arg_process_vm;                            //attempt writes using process_vm_writev
    bool arg_func_only;                             //only show func symbols
    char* arg_symbol_filter;                        //symbol name to filter for
    char* arg_library_filter;                       //library name to filter for
} args_t;

/*Prototypes*/
off_t write_payload(pid_t, void*, size_t, void*, args_t*);
match_t* find_segments(pid_t, char*, match_t*, args_t *);  
export_t* find_exports(match_t*, bool, export_t*, args_t *);
void* get_cmdline(pid_t);

#endif