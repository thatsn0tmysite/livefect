#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

match_t *find_segments(pid_t pid, char *perms, match_t *matches, args_t *args) {
  FTS *fts;
  FTSENT *entry, *child;

  int finds = 0; // matching segments found
  if (strlen(perms) != 4) {
    fprintf(stderr, "[E] Invalid perms (%s) %d\n", perms, (int)strlen(perms));
    return NULL;
  }

  char *proc_path[] = {"/proc/", NULL};
  if ((fts = fts_open(proc_path, FTS_LOGICAL, NULL)) == NULL) {
    fprintf(stderr, "[E] Error traversing /proc. (errno: %d)", errno);
    exit(EXIT_FAILURE);
  }

  while ((entry = fts_read(fts)) != NULL) {
    child = fts_children(fts, 0);
    if (child == NULL) {
      break;
    }

    while (child) {
      switch (child->fts_info) {
      case FTS_D:
        if (atoi(child->fts_name) != 0) {
          // We have a valid PID
          // printf("Entry: %s of type %d\n", child->fts_name, child->fts_info);

          // Be selective if a pid was specified
          if (pid > 0 && atoi(child->fts_name) != pid)
            break;

          if (args->arg_verbosity > 1)
            printf("[+] Found PID: %d\n", atoi(child->fts_name));

          // Construct path
          char *maps_path =
              (char *)malloc(strlen("/proc//maps") + entry->fts_namelen + 1);
          sprintf(maps_path, "/proc/%d/maps", atoi(child->fts_name));

          FILE *f_maps = fopen(maps_path, "r");
          if (f_maps == NULL) {
            fprintf(stderr, "[E] Error reading file: %s (errno: %d)\n",
                    maps_path, errno);
          }

          // Iterate through /proc/pid/maps
          size_t line_size = 0;
          char *line = NULL;

          // printf("Reading /proc/%d/maps file...\n",atoi(child->fts_name));
          while (getline(&line, &line_size, f_maps) != -1) {
            maps_entry_t maps_entry;
            memset(maps_entry.path, 0, 513);

            sscanf(line, "%p-%p %c%c%c%c %Lx %x:%x %x %512c", &maps_entry.start,
                   &maps_entry.end, &maps_entry.flags[0], &maps_entry.flags[1],
                   &maps_entry.flags[2], &maps_entry.flags[3],
                   &maps_entry.file_offset, &maps_entry.dev_major,
                   &maps_entry.dev_minor, &maps_entry.inode, maps_entry.path);
            maps_entry.path[strcspn(maps_entry.path, "\n")] =
                0; // NULL terminate path

            // maps_entries=maps_entry_push(maps_entries, &maps_entry);
            if (args->arg_verbosity > 1) {
              printf("\t%s", line);
            }

            int matched = 0;
            for (int i = 0; i < strlen(perms); i++) {
              if (perms[i] == maps_entry.flags[i] || perms[i] == '*') {
                matched++;
              }
            }

            if (matched == 4) {
              // printf("\t[+] %d Matching (%c%c%c%c) region found: %p-%p\n",
              // finds, perms[0],perms[1], perms[2], perms[3], last_start,
              // last_end);
              match_t_push(&matches, atoi(child->fts_name), maps_entry.start,
                           maps_entry.end, maps_entry.flags, maps_entry.path);
              finds++;
            }
          }

          // free(last_path);
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

export_t *find_exports(match_t *matches, bool from_disk, export_t *exports,
                       args_t *args) {
  // https://gist.github.com/DhavalKapil/2243db1b732b211d0c16fd5d9140ab0b
  // https://jvns.ca/blog/2018/01/09/resolving-symbol-addresses/
  // https://gist.github.com/tangrs/4030336

  char *elf_path;
  int fd, finds = 0;
  char *buff = NULL;
  size_t buff_len = 0;

  match_t *match = matches;
  while (match) {
    if (from_disk) {
      if (args->arg_verbosity > 4)
        printf("[*] Attempting load of ELF from disk: %s\n", match->path);
      elf_path = match->path;
    } else {
      // if(args->arg_verbosity>4)
      printf("[W] WIP. Use -F for now! Attempting load of ELF from memory: %p "
             "(%lu bytes)\n",
             match->start, (match->end - match->start));
      // exit(EXIT_FAILURE);

      int c = 0;
      int n = match->pid;
      do {
        n /= 10;
        ++c;
      } while (n != 0);

      elf_path = malloc(strlen("/proc//exe") + c);
      sprintf(elf_path, "/proc/%d/exe", match->pid);
    }

    fd = open(elf_path, O_RDONLY);
    if (fd < 0) {
      if (args->arg_verbosity > 2)
        fprintf(stderr, "[E] Error opening file: %s (errno: %d)\n", match->path,
                errno);
      if (!from_disk)
        free(elf_path);
      match = match->next;
      continue;
    }

    // Get filesize
    buff_len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET); // rewind

    buff = (char *)calloc(buff_len, sizeof(char));

    // Read all into buff
    int bytes_read = read(fd, buff, buff_len);

    // Close file
    close(fd);

    if (bytes_read < 0) {
      if (args->arg_verbosity > 2)
        fprintf(stderr, "[W] Error: failed reading bytes (char device?) %d.\n",
                errno);
      free(buff);
      if (!from_disk)
        free(elf_path);
      match = match->next;
      continue;
    }

    /**Finds exports section in ELF file*/
    ElfW(Ehdr) *header = (ElfW(Ehdr) *)((char *)buff);
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
      if (args->arg_verbosity > 2)
        fprintf(stderr, "[W] Invalid ELF: %s\n", match->path);
      free(buff);
      if (!from_disk)
        free(elf_path);
      match = match->next;
      continue;
    }

    // We SHOULD have a valid ELF file
    ElfW(Shdr) *sections = (ElfW(Shdr) *)((char *)buff + header->e_shoff);
    char *section_names =
        (char *)(buff + sections[header->e_shstrndx].sh_offset);
    ElfW(Sym) * symtab;

    void *local_shoff = buff + header->e_shoff;
    void *remote_shoff = match->start + header->e_shoff;

    if (args->arg_verbosity > 3)
      printf("\t[+] Possible %c%c%c%c section header @ [L:%lu][R:%p] (%d "
             "entries) for %s\n",
             buff[0], buff[1], buff[2], buff[3], header->e_shoff, remote_shoff,
             header->e_shnum, match->path);

    for (int i = 0; i < header->e_shnum; i++) {
      if (sections[i].sh_type == SHT_SYMTAB ||
          sections[i].sh_type == SHT_DYNSYM) {
        symtab = (ElfW(Sym) *)(buff + sections[i].sh_offset);
        if (args->arg_verbosity > 2)
          printf("\t[+] Symbols table %s @ [L:%p][R:%p] for %s\n",
                 (section_names + sections[i].sh_name), local_shoff,
                 match->start + sections[i].sh_offset, match->path);

        int symbol_num = sections[i].sh_size / sections[i].sh_entsize;
        char *symbol_names =
            (char *)(buff + sections[sections[i].sh_link].sh_offset);

        for (int j = 0; j < symbol_num - 1; j++) {
          if (args->arg_verbosity > 3)
            printf("\t\t%s Addr: %lx (%lu bytes) [L:%p][R:%p]: \"%s\"\t\n",
                   match->path, symtab[j].st_value, symtab[j].st_size,
                   buff + symtab[j].st_value, match->start + symtab[j].st_value,
                   symbol_names + symtab[j].st_name);

          /*Filter by symbol/library and st_info type*/
          // Filter order is important (DATA>FUNC>LIBRARY>SYMBOL)
          if (args->arg_data_only && symtab[j].st_info != STT_OBJECT)
            continue;
          if (args->arg_func_only && symtab[j].st_info != STT_FUNC)
            continue;
          if (args->arg_library_filter &&
              strcmp(match->path, args->arg_library_filter) != 0)
            continue;
          if (args->arg_symbol_filter &&
              strstr(symbol_names + symtab[j].st_name,
                     args->arg_symbol_filter) == NULL)
            continue;

          // TODO: fix this, symbols offsets seem to be of by 0x1000
          export_t_push(&exports, match->pid, strdup(match->perms),
                        strdup(symbol_names + symtab[j].st_name),
                        (match->start + symtab[j].st_value), symtab[j].st_size);
          finds++;
        }
      }
    }

    if (!from_disk)
      free(elf_path);
    free(buff);
    match = match->next;
  }
  return exports;
}

off_t write_payload(pid_t pid, void *payload, size_t payload_len, void *dst,
                    args_t *args) {
  if (args->arg_process_vm) {
    // TODO: keep the option to force using process_vm_writev, even if not as
    // effective. Add command line flag.
    fprintf(stderr, "[E] Feature not implemented yet.\n");
    return -2;
  }

  // We basically doing this: sudo dd seek=$((0x7ff5c451d109)) bs=1B
  // if=shellcodes/shellcode_demo of=/proc/12443/mem
  if (pid < 1) {
    fprintf(stderr, "[E] Invalid PID: %d\n", pid);
    return -1;
  }

  // Count digits
  int c = 0;
  int n = pid;
  do {
    n /= 10;
    ++c;
  } while (n != 0);

  // Construct path
  char *memfd_path = (char *)malloc(strlen("/proc//mem") + c + 1);
  sprintf(memfd_path, "/proc/%ld/mem", (unsigned long)pid);

  // Open, seek, write
  int memfd = open(memfd_path, O_WRONLY | O_RDONLY);
  if (memfd == -1) {
    fprintf(stderr, "[E] Failed to open '%s' (errno: %d)\n", memfd_path, errno);
    return -1;
  }

  printf("[*] Seeking @ %d (%p)\n", (int)lseek(memfd, (off_t)dst, SEEK_SET),
         dst);
  int err = (int)write(memfd, payload, payload_len);
  close(memfd);

  if (err != -1)
    printf("[*] Wrote %d bytes\n", err);
  else
    return -1;

  return 0;
}

void *get_cmdline(pid_t pid) {
  if (pid == 0)
    return NULL;

  int n = pid;
  int n_digits = 0;
  while (n != 0) {
    n = n / 10;
    ++n_digits;
  }

  char *cmdline_path = (char *)malloc(strlen("/proc//comm") + n_digits);
  if (cmdline_path == NULL)
    return NULL;

  sprintf(cmdline_path, "/proc/%d/comm", pid);

  char *cmdline = (char *)malloc(257); // caller frees
  if (cmdline == NULL) {
    free(cmdline_path);
    return NULL;
  }
  memset(cmdline, 0, 257);

  int cmdline_fd = open(cmdline_path, O_RDONLY);
  if (cmdline_fd < 0) {
    free(cmdline_path);
    free(cmdline);
    return NULL;
  }

  read(cmdline_fd, cmdline, 257); // TODO: check read
  cmdline[strcspn(cmdline, "\n")] = 0;

  close(cmdline_fd);
  free(cmdline_path);
  return (void *)cmdline;
}