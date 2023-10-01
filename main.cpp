#include <capstone/capstone.h>
#include <cstddef>
#include <cstdint>
#include <curses.h>
#include <elf.h>
#include <inttypes.h>
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

class __WINDOW {
public:
  WINDOW *window;

  __WINDOW(char *title, int h, int w, int y, int x) {
    this->title = title;
    this->h = h;
    this->w = w;
    this->y = y;
    this->x = x;

    draw();
  }

  WINDOW *draw() {
    WINDOW *win = newwin(h, w, y, x);
    window = win;
    box(win, 0, 0);
    scrollok(win, true);
    touchwin(win);
    mvwprintw(win, 0, 2, "%s", (char *)title);
    wrefresh(win);
    return win;
  }

private:
  char *title;
  int h, w, y, x;
};

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("Usage: %s <ELF binary>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  char *filename = argv[1];

  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    perror("Failed to open file");
    exit(EXIT_FAILURE);
  }

  Elf64_Ehdr header;
  fread(&header, sizeof(header), 1, file);
  if (header.e_ident[EI_MAG0] != ELFMAG0 ||
      header.e_ident[EI_MAG1] != ELFMAG1 ||
      header.e_ident[EI_MAG2] != ELFMAG2 ||
      header.e_ident[EI_MAG3] != ELFMAG3) {
    printf("%s is not a valid ELF binary\n", filename);
    exit(EXIT_FAILURE);
  }

  if (header.e_ident[EI_CLASS] != ELFCLASS64) {
    printf("%s is not a 64-bit ELF binary\n", filename);
    exit(EXIT_FAILURE);
  }

  if (header.e_shoff == 0 || header.e_shnum == 0) {
    printf("%s does not have a section header table\n", filename);
    exit(EXIT_FAILURE);
  }

  Elf64_Shdr section_header;

  fseek(file, header.e_shoff + header.e_shstrndx * sizeof(section_header),
        SEEK_SET);
  fread(&section_header, sizeof(section_header), 1, file);

  char *section_name_table = (char *)malloc(section_header.sh_size);
  fseek(file, section_header.sh_offset, SEEK_SET);
  fread(section_name_table, section_header.sh_size, 1, file);

  csh handle;
  cs_insn *insn;
  size_t count;

  for (int i = 0; i < header.e_shnum; i++) {
    fseek(file, header.e_shoff + i * sizeof(section_header), SEEK_SET);
    fread(&section_header, sizeof(section_header), 1, file);
    char *section_name = section_name_table + section_header.sh_name;
    if (section_header.sh_type == SHT_PROGBITS &&
        strcmp(section_name, ".text") == 0) {
      char *section_data = (char *)malloc(section_header.sh_size);
      fseek(file, section_header.sh_offset, SEEK_SET);
      fread(section_data, section_header.sh_size, 1, file);

      if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;
      count = cs_disasm(handle, (uint8_t *)section_data, section_header.sh_size,
                        header.e_entry, 0, &insn);

      free(section_data);
    }
  }

  initscr();
  noecho();
  refresh();
  curs_set(0);

  int height, width;
  getmaxyx(stdscr, height, width);

  __WINDOW *asmWindow =
      new __WINDOW((char *)"asm", height * 0.75, width * 0.45, 0, 0);
  __WINDOW *ioWindow =
      new __WINDOW((char *)"io", height * 0.25, width * 0.45, height * 0.75, 0);
  __WINDOW *memdumpWindow = new __WINDOW((char *)"mem dump", height * 0.64,
                                         width * 0.55, 0, width * 0.455);
  __WINDOW *regWindow = new __WINDOW((char *)"reg", height * 0.37, width * 0.55,
                                     height * 0.64, width * 0.455);

  if (count > 0) {
    pid_t child;
    const int long_size = sizeof(long);
    child = fork();

    if (child == 0) {
      ptrace(PTRACE_TRACEME, 0, NULL, NULL);
      execl(filename, filename, NULL);
    } else {

      // print the assembly in asm window
      for (int i = 0; i < count; i++) {
        mvwprintw(asmWindow->window, i + 2, 5, "0x%" PRIx64 ":  %s\t %s",
                  insn[i].address, insn[i].mnemonic, insn[i].op_str);
      }
      wrefresh(asmWindow->window);

      int status;
      struct user_regs_struct regs;
      int i = 0;

      while (1) {
        wait(&status);

        if (WIFEXITED(status))
          break;

        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        wattron(asmWindow->window, A_REVERSE);
        mvwprintw(asmWindow->window, i + 2, 5, "0x%" PRIx64 ":  %s\t %s",
                  insn[i].address, insn[i].mnemonic, insn[i].op_str);
        wrefresh(asmWindow->window);
        wattroff(asmWindow->window, A_REVERSE);

        mvwprintw(regWindow->window, 2, 5, "rip: 0x%016llx", regs.rip);
        mvwprintw(regWindow->window, 3, 5, "rsp: 0x%016llx", regs.rsp);
        mvwprintw(regWindow->window, 4, 5, "rax: 0x%016llx", regs.rax);
        mvwprintw(regWindow->window, 5, 5, "rdi: 0x%016llx", regs.rdi);
        mvwprintw(regWindow->window, 6, 5, "rsi: 0x%016llx", regs.rsi);
        mvwprintw(regWindow->window, 7, 5, "rdx: 0x%016llx", regs.rdx);
        mvwprintw(regWindow->window, 8, 5, "rcx: 0x%016llx", regs.rcx);
        mvwprintw(regWindow->window, 9, 5, "rbx: 0x%016llx", regs.rbx);
        mvwprintw(regWindow->window, 10, 5, "rbp: 0x%016llx", regs.rbp);

        mvwprintw(regWindow->window, 2, 32, "r8:    0x%016llx", regs.r8);
        mvwprintw(regWindow->window, 3, 32, "r9:    0x%016llx", regs.r9);
        mvwprintw(regWindow->window, 4, 32, "r10:   0x%016llx", regs.r10);
        mvwprintw(regWindow->window, 5, 32, "r11:   0x%016llx", regs.r11);
        mvwprintw(regWindow->window, 6, 32, "r12:   0x%016llx", regs.r12);
        mvwprintw(regWindow->window, 7, 32, "r13:   0x%016llx", regs.r13);
        mvwprintw(regWindow->window, 8, 32, "r14:   0x%016llx", regs.r14);
        mvwprintw(regWindow->window, 9, 32, "r15:   0x%016llx", regs.r15);
        mvwprintw(regWindow->window, 10, 32, "eflag: 0x%016llx", regs.eflags);

        mvwprintw(regWindow->window, 2, 61, "ss:    0x%016llx", regs.ss);
        mvwprintw(regWindow->window, 3, 61, "cs:    0x%016llx", regs.cs);
        mvwprintw(regWindow->window, 4, 61, "ds:    0x%016llx", regs.ds);
        mvwprintw(regWindow->window, 5, 61, "es:    0x%016llx", regs.es);
        mvwprintw(regWindow->window, 6, 61, "fs:    0x%016llx", regs.fs);
        mvwprintw(regWindow->window, 7, 61, "gs:    0x%016llx", regs.gs);
        mvwprintw(regWindow->window, 8, 61, "fs_b:  0x%016llx", regs.fs_base);
        mvwprintw(regWindow->window, 9, 61, "gs_b:  0x%016llx", regs.gs_base);
        mvwprintw(regWindow->window, 10, 61, "o_rax: 0x%016llx", regs.orig_rax);

        wrefresh(regWindow->window);

        if (char ch = getch() == '\n') {
          mvwprintw(asmWindow->window, i + 2, 5, "0x%" PRIx64 ":  %s\t %s",
                    insn[i].address, insn[i].mnemonic, insn[i].op_str);
          ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
          i++;
        }
      }
    }

    cs_free(insn, count);
  } else
    printf("ERROR: Failed to disassemble given code!\n");

  getchar();
  endwin();
  cs_close(&handle);
  free(section_name_table);
  fclose(file);
  exit(EXIT_SUCCESS);
}