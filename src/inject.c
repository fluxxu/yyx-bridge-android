#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <errno.h>

extern uint32_t _inject_start_s;
extern uint32_t _inject_end_s;

extern uint32_t get_code_length()
{
  return (uint32_t)&_inject_end_s - (uint32_t)&_inject_start_s;
}

extern void *get_code_addr()
{
  return (void *)&_inject_start_s;
}

extern int ptrace_attach(pid_t pid)
{
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
  {
    return 0;
  }

  waitpid(pid, NULL, WUNTRACED);

  if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0)
  {
    return 0;
  }

  waitpid(pid, NULL, WUNTRACED);

  return 1;
}

extern int ptrace_detach(pid_t pid)
{
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
  {
    printf("detach error: %s\n", strerror(errno));
    return 0;
  }

  return 1;
}

extern void *ptrace_new_regs()
{
  void *regs = malloc(sizeof(struct pt_regs));
  memset(regs, 0, sizeof(struct pt_regs));
  return regs;
}

extern int ptrace_get_regs(pid_t pid, struct pt_regs *regs)
{
  if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1)
  {
    return 0;
  }

  return 1;
}

extern int ptrace_set_regs(pid_t pid, struct pt_regs *regs)
{
  if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1)
  {
    return 0;
  }

  return 1;
}

extern void *ptrace_clone_regs(struct pt_regs *regs)
{
  void *cloned = ptrace_new_regs();
  memcpy(cloned, regs, sizeof(struct pt_regs));
  return cloned;
}

extern uint32_t ptrace_get_esp(struct pt_regs *regs)
{
  return regs->esp;
}

extern int ptrace_set_esp(pid_t pid, struct pt_regs *regs, uint32_t esp)
{
  struct pt_regs update;
  memcpy(&update, regs, sizeof(struct pt_regs));
  update.esp = esp;
  return ptrace(PTRACE_SETREGS, pid, NULL, &update) >= 0;
}

extern void ptrace_free_regs(void *regs)
{
  free(regs);
}

int ptrace_read(pid_t pid, void *addr, void *buf, uint32_t buf_size)
{
  if (buf_size <= 4)
  {
    uint32_t val = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
    memcpy(buf, &val, buf_size);
    return 1;
  }

  int n = buf_size / 4, need_pad = 0;
  if (buf_size % 4 > 0)
  {
    n++;
    need_pad = 1;
  }
  for (int i = 0; i < n; i++)
  {
    uint32_t offset = i * 4;
    void *p = (void *)(addr + offset);
    void *buf_p = buf + offset;
    uint32_t val = ptrace(PTRACE_PEEKTEXT, pid, p, 0);
    if (i == n - 1 && need_pad == 1)
    {
      memcpy(buf_p, &val, buf_size - offset);
    }
    else
    {
      memcpy(buf_p, &val, 4);
    }
  }
  return 1;
}

int ptrace_write(pid_t pid, void *addr, void *data, uint32_t data_size)
{
  if (data_size < 4)
  {
    uint32_t val = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    memcpy(&val, data, data_size);
    return ptrace(PTRACE_POKETEXT, pid, addr, (void *)val) >= 0;
  }

  int n = data_size / 4, need_pad = 0;
  if (data_size % 4 > 0)
  {
    n++;
    need_pad = 1;
  }

  // printf("ptrace_write: data_size = 0x%x, n = %u, need_pad = %u\n", data_size, n, need_pad);

  for (int i = 0; i < n; i++)
  {
    uint32_t offset = i * 4;
    void *p = (void *)(addr + offset);
    uint32_t val = 0;
    if (i == n - 1 && need_pad == 1)
    {
      ptrace_read(pid, p, (void *)&val, 4);
      memcpy(&val, data + offset, data_size - offset);
    }
    else
    {
      memcpy(&val, data + offset, 4);
    }
    // printf("ptrace_write: %d:0x%x = 0x%x\n", i, p, val);
    int rv = ptrace(PTRACE_POKETEXT, pid, p, (void *)val);
    if (rv < 0)
    {
      return 0;
    }
  }
  return 1;
}

int ptrace_continue(pid_t pid)
{
  if (ptrace(PTRACE_CONT, pid, NULL, 0) == -1)
  {
    return 0;
  }

  return 1;
}

int ptrace_system_call(pid_t pid, uint32_t addr, uint32_t *args, uint32_t argc, struct pt_regs *regs, uint32_t *rv)
{
  struct pt_regs local_regs;
  memcpy(&local_regs, regs, sizeof(struct pt_regs));

  uint32_t stack_size = sizeof(uint32_t) * (argc + 1);

  local_regs.esp = local_regs.esp - stack_size;

  uint32_t stack_start = local_regs.esp;
  void *stack_bkup = alloca(stack_size);

  if (0 == ptrace_read(pid, (void *)stack_start, stack_bkup, stack_size))
  {
    return 0;
  }

  uint32_t fake_addr = 0;

  if (0 == ptrace_write(pid, (void *)stack_start, &fake_addr, 4))
  {
    return 0;
  }

  local_regs.eip = addr;

  if (0 == ptrace_write(pid, (void *)local_regs.esp + 4, (void *)args, stack_size - 4))
  {
    return 0;
  }

  // local_regs.eax = argc;

  if (ptrace_set_regs(pid, &local_regs) == 0)
  {
    return 0;
  }

  if (ptrace_continue(pid) == 0)
  {
    return 0;
  }

  waitpid(pid, NULL, WUNTRACED);

  if (ptrace_get_regs(pid, &local_regs) == 0)
  {
    return 0;
  }

  *rv = local_regs.eax;

  if (ptrace_write(pid, (void *)stack_start, stack_bkup, stack_size) == 0)
  {
    return 0;
  }

  return 1;
}

struct remove_load_lib_params
{
  pid_t pid;
  struct pt_regs *regs;
  void *mem;
  uint32_t mem_size;
  void *dlopen_addr;
  char *lib_path;
  int flags;
};

int remote_load_lib(struct remove_load_lib_params *params)
{
  const uint32_t stack_size = 0x10000;
  uint32_t code_size = get_code_length();
  uint32_t lib_path_size = strlen(params->lib_path) + 1;
  uint32_t buf_size = stack_size + code_size + lib_path_size;

  // void *code_addr = get_code_addr();
  // printf("code addr = 0x%x\n", (uint32_t)code_addr);
  // printf("code size = 0x%x\n", code_size);
  // printf("lib path size = 0x%x\n", lib_path_size);
  // printf("buf size = 0x%x\n", buf_size);

  // for (uint32_t i = 0; i < code_size; i++)
  // {
  //   printf("0x%x\n", ((uint8_t *)&_inject_start_s)[i]);
  // }

  void *buf = malloc(buf_size);
  memset(buf, 0, buf_size);
  memcpy(buf + stack_size, &_inject_start_s, code_size);
  memcpy(buf + stack_size + code_size, params->lib_path, lib_path_size);

  uint32_t args[] = {(uint32_t)params->mem + stack_size + code_size, RTLD_NOW};
  memcpy(buf + stack_size - 8, &args, 8);

  if (ptrace_write(params->pid, params->mem, buf, buf_size) == 0)
  {
    goto fail;
  }

  struct pt_regs local_regs;
  memcpy(&local_regs, params->regs, sizeof(struct pt_regs));

  local_regs.eax = (uint32_t)params->dlopen_addr;
  local_regs.esp = (uint32_t)params->mem + stack_size - 8;
  local_regs.eip = (uint32_t)params->mem + stack_size;

  if (ptrace_set_regs(params->pid, &local_regs) == 0)
  {
    goto fail;
  }

  if (ptrace_continue(params->pid) == 0)
  {
    return 0;
  }
  waitpid(params->pid, NULL, WUNTRACED);

  free(buf);
  return 1;

fail:
  free(buf);
  return 0;
}

#define OK(op, msg)             \
  if (op == -1)                 \
  {                             \
    printf("error: %s\n", msg); \
    return;                     \
  }

extern void test(pid_t pid)
{
  OK(ptrace_attach(pid), "attach")
  OK(ptrace_detach(pid), "detach")
}