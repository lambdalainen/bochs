/////////////////////////////////////////////////////////////////////////
// $Id: cpu.cc 12894 2016-02-22 19:57:24Z sshwarts $
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2015  The Bochs Project
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA
/////////////////////////////////////////////////////////////////////////

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#define LOG_THIS BX_CPU_THIS_PTR

#include "cpustats.h"

#include "disasm/disasm.h"

// Features we support:
//
// 1. 4 regular breakpoints: break at an address
// 1. 4 regular watchpoints for byte, word, and dword: print info when a value is
//    written to a memory address. This works under tracing mode. Tracing starts
//    when search_string_read is read from memory, and stops when
//    search_string_write is written to memory.
// 3. Break when any register contains a target value.

Bit64u rip_trace[10000];
long   rip_idx;

bx_address breakpoint[4];

bx_address watch_byte[4];
bx_address watch_word[4];
bx_address watch_dword[4];
bx_bool    is_tracing = 0;

char search_string_read[1024];
int  search_string_read_length;
char search_string_write[1024];
int  search_string_write_length;

Bit32u     reg_target   = 0;
bx_bool    watch_reg    = 0;
bx_bool    should_break = 0;

static disassembler bx_disassemble;
static Bit8u        bx_disasm_ibuf[32];
static char         bx_disasm_tbuf[512];

bx_bool bx_dbg_read_linear(unsigned which_cpu, bx_address laddr, unsigned len, Bit8u *buf)
{
  unsigned remainsInPage;
  bx_phy_address paddr;
  unsigned read_len;
  bx_bool paddr_valid;

next_page:
  remainsInPage = 0x1000 - PAGE_OFFSET(laddr);
  read_len = (remainsInPage < len) ? remainsInPage : len;

  paddr_valid = BX_CPU(which_cpu)->dbg_xlate_linear2phy(laddr, &paddr);
  if (paddr_valid) {
    if (! BX_MEM(0)->dbg_fetch_mem(BX_CPU(which_cpu), paddr, read_len, buf)) {
      printf("bx_dbg_read_linear: physical memory read error (phy=0x" FMT_PHY_ADDRX ", lin=0x" FMT_ADDRX ")\n", paddr, laddr);
      return 0;
    }
  }
  else {
    printf("bx_dbg_read_linear: physical address not available for linear 0x" FMT_ADDRX "\n", laddr);
    return 0;
  }

  /* check for access across multiple pages */
  if (remainsInPage < len)
  {
    laddr += read_len;
    len -= read_len;
    buf += read_len;
    goto next_page;
  }

  return 1;
}

void bx_dbg_disassemble_command(const char *format, Bit64u from, Bit64u to)
{
  int numlines = INT_MAX;
  int dbg_cpu = 0;

  if (from > to) {
     Bit64u temp = from;
     from = to;
     to = temp;
  }

  if (format) {
    // format always begins with '/' (checked in lexer)
    // so we won't bother checking it here second time.
    numlines = atoi(format + 1);
    if (to == from)
      to = BX_MAX_BIT64U; // Disassemble just X lines
  }

  unsigned dis_size = 0; //bx_debugger.disassemble_size;
  if (dis_size == 0) {
    dis_size = 16;     // until otherwise proven
    if (BX_CPU(dbg_cpu)->sregs[BX_SEG_REG_CS].cache.u.segment.d_b)
      dis_size = 32;
    if (BX_CPU(dbg_cpu)->get_cpu_mode() == BX_MODE_LONG_64)
      dis_size = 64;
  }

  FILE *fp = fopen("disassembled.txt", "a");
  fprintf(fp, ">>>>>>>>>> Starting new disassembly\n");

  do {
    numlines--;

    if (! bx_dbg_read_linear(dbg_cpu, from, 16, bx_disasm_ibuf)) break;

    unsigned ilen = bx_disassemble.disasm(dis_size==32, dis_size==64,
       (bx_address)(-1), (bx_address)(-1), bx_disasm_ibuf, bx_disasm_tbuf);

    fprintf(fp, "%08x: ", (unsigned) from);
    fprintf(fp, "%-25s ; ", bx_disasm_tbuf);

    for (unsigned j=0; j<ilen; j++)
      fprintf(fp, "%02x", (unsigned) bx_disasm_ibuf[j]);
    fprintf(fp, "\n");

    from += ilen;
  } while ((from < to) && numlines > 0);

  fprintf(fp, "<<<<<<<<<<  Disassembly ends\n");

  fclose(fp);
}

// format = "/1234"
void bx_dbg_examine_command(const char *format, bx_address addr)
{
  int      dbg_cpu = 0;
  unsigned repeat_count, i;
  char     ch;
  unsigned data_size = 1;
  Bit8u    data8;
  unsigned columns, per_line = 8, offset = 0;
  Bit8u    databuf[8];

  printf("[bochs]:\n");

  format++;
  repeat_count = 0;
  ch = *format;

  while (ch>='0' && ch<='9') {
  repeat_count = 10*repeat_count + (ch-'0');
  format++;
    ch = *format;
  }

  columns = per_line + 1; // set current number columns past limit

  for (i = 1; i <= repeat_count; i++) {
    if (columns > per_line) {
      // if not 1st run, need a newline from last line
      if (i!=1)
        printf("\n");
      printf("0x" FMT_ADDRX " <bogus+%8u>:", addr, offset);
      columns = 1;
    }

    if (! bx_dbg_read_linear(dbg_cpu, addr, data_size, databuf))
    return;

  data8 = databuf[0];
  printf("\t0x%02x", (unsigned) data8);

    addr += data_size;
    columns++;
    offset += data_size;
  }
  printf("\n");
}

void BX_CPU_C::cpu_loop(void)
{
#if BX_DEBUGGER
  BX_CPU_THIS_PTR break_point = 0;
  BX_CPU_THIS_PTR magic_break = 0;
  BX_CPU_THIS_PTR stop_reason = STOP_NO_REASON;
#endif

  if (setjmp(BX_CPU_THIS_PTR jmp_buf_env)) {
    // can get here only from exception function or VMEXIT
    BX_CPU_THIS_PTR icount++;
    BX_SYNC_TIME_IF_SINGLE_PROCESSOR(0);
#if BX_DEBUGGER || BX_GDBSTUB
    if (dbg_instruction_epilog()) return;
#endif
#if BX_GDBSTUB
    if (bx_dbg.gdbstub_enabled) return;
#endif
  }

  // If the exception() routine has encountered a nasty fault scenario,
  // the debugger may request that control is returned to it so that
  // the situation may be examined.
#if BX_DEBUGGER
  if (bx_guard.interrupt_requested) return;
#endif

  // We get here either by a normal function call, or by a longjmp
  // back from an exception() call.  In either case, commit the
  // new EIP/ESP, and set up other environmental fields.  This code
  // mirrors similar code below, after the interrupt() call.
  BX_CPU_THIS_PTR prev_rip = RIP; // commit new EIP
  BX_CPU_THIS_PTR speculative_rsp = 0;

  while (1) {

    // check on events which occurred for previous instructions (traps)
    // and ones which are asynchronous to the CPU (hardware interrupts)
    if (BX_CPU_THIS_PTR async_event) {
      if (handleAsyncEvent()) {
        // If request to return to caller ASAP.
        return;
      }
    }

    bxICacheEntry_c *entry = getICacheEntry();
    bxInstruction_c *i = entry->i;

#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS
    for(;;) {
      // want to allow changing of the instruction inside instrumentation callback
      BX_INSTR_BEFORE_EXECUTION(BX_CPU_ID, i);
      RIP += i->ilen();
      // when handlers chaining is enabled this single call will execute entire trace
      BX_CPU_CALL_METHOD(i->execute1, (i)); // might iterate repeat instruction
      BX_SYNC_TIME_IF_SINGLE_PROCESSOR(0);

      if (BX_CPU_THIS_PTR async_event) break;

      i = getICacheEntry()->i;
    }
#else // BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS == 0

    bxInstruction_c *last = i + (entry->tlen);

    for(;;) {

#if BX_DEBUGGER
      if (BX_CPU_THIS_PTR trace)
        debug_disasm_instruction(BX_CPU_THIS_PTR prev_rip, 0);
#endif

      // want to allow changing of the instruction inside instrumentation callback
      BX_INSTR_BEFORE_EXECUTION(BX_CPU_ID, i);
      RIP += i->ilen();
      BX_CPU_CALL_METHOD(i->execute1, (i)); // might iterate repeat instruction

#if 0
      rip_trace[rip_idx++] = BX_CPU_THIS_PTR prev_rip;
      if (rip_idx == 10000)
          rip_idx = 0;

      char buf[8];
      printf("Disassemble rip_trace? [y/n/s(kip)] ");
      scanf("%s", buf);
      if (buf[0] == 'y') {
        printf("--- rip_idx: %li\n", rip_idx);
        for (int idx = rip_idx; idx < 10000; idx++) {
          bx_dbg_disassemble_command(NULL, rip_trace[idx], rip_trace[idx]);
        }
        for (int idx = 0; idx < rip_idx; idx++) {
          bx_dbg_disassemble_command(NULL, rip_trace[idx], rip_trace[idx]);
        }
      }
#endif

      // tracing is only triggered by search_string_read and search_string_write
      if (is_tracing) {
          debug_disasm_instruction(BX_CPU_THIS_PTR prev_rip, 0);
          BX_INFO(("### After RIP %08x:", BX_CPU_THIS_PTR prev_rip));
          BX_INFO(("| EAX=%08x  EBX=%08x  ECX=%08x  EDX=%08x", (unsigned) EAX, (unsigned) EBX, (unsigned) ECX, (unsigned) EDX));
          BX_INFO(("| ESP=%08x  EBP=%08x  ESI=%08x  EDI=%08x", (unsigned) ESP, (unsigned) EBP, (unsigned) ESI, (unsigned) EDI));
      }

      if (watch_reg) {
          if (EAX == reg_target ||
              EBX == reg_target ||
              ECX == reg_target ||
              EDX == reg_target ||
              ESI == reg_target ||
              EDI == reg_target)
          {
              debug_disasm_instruction(BX_CPU_THIS_PTR prev_rip, 1);
              printf("### Got %x: after RIP %08x:\n", reg_target, BX_CPU_THIS_PTR prev_rip);
              printf("| EAX=%08x  EBX=%08x  ECX=%08x  EDX=%08x\n", (unsigned) EAX, (unsigned) EBX, (unsigned) ECX, (unsigned) EDX);
              printf("| ESP=%08x  EBP=%08x  ESI=%08x  EDI=%08x\n", (unsigned) ESP, (unsigned) EBP, (unsigned) ESI, (unsigned) EDI);
          }
      }

      if (!should_break) {
          for (int i = 0; i < 4; i++) {
              if (EIP == breakpoint[i]) {
                  printf("\n=====> hit breakpoint: %08x\n", EIP);
                  should_break = 1;
                  break;
              }
          }
      } else {
          printf("Previous instruction at %08x:\n", BX_CPU_THIS_PTR prev_rip);
          debug_disasm_instruction(BX_CPU_THIS_PTR prev_rip, 1);
          printf("### After RIP %08x:\n", BX_CPU_THIS_PTR prev_rip);
          printf("| EAX=%08x  EBX=%08x  ECX=%08x  EDX=%08x\n", (unsigned) EAX, (unsigned) EBX, (unsigned) ECX, (unsigned) EDX);
          printf("| ESP=%08x  EBP=%08x  ESI=%08x  EDI=%08x\n\n", (unsigned) ESP, (unsigned) EBP, (unsigned) ESI, (unsigned) EDI);

          bx_address addr;

          while (1)
          {
              char buf[16];
              printf("(n)ext | (c)ont | (d)isasm | e(x/N)amine | (b)p | reg_(t)arget | (rw)_str | (1|2|4)watchpoint | (D)el: " );
              scanf("%s", buf);
              if (buf[0] == 'n')
              {
                  break;
              }
              else if (buf[0] == 'c')
              {
                  should_break = 0;
                  break;
              }
              else if (buf[0] == 'd')
              {
                  bx_address from;
                  bx_address to;
                  printf("Enter the FROM address to disassemble: ");
                  scanf("%x", &from);
                  printf("Enter the TO address to disassemble: ");
                  scanf("%x", &to);

                  bx_dbg_disassemble_command(NULL, from, to);
                  break;
              }
              else if (buf[0] == 'x')
              {
                  printf("Address to examine memory content: ");
                  scanf("%x", &addr);
                  // '/N' is handled by bx_dbg_examine_command
                  bx_dbg_examine_command(buf+1, addr);
              }
              else if (buf[0] == 'b')
              {
                  printf("Address to break: ");
                  scanf("%x", &addr);
                  int i;
                  for (i = 0; i < 4; i++) {
                      if (breakpoint[i] == 0) {
                          breakpoint[i] = addr;
                          break;
                      }
                  }
                  if (i == 4) {
                      printf("Only 4 breakpoints supported\n");
                  }
                  printf("Breakpoints:\n");
                  for (i = 0; i < 4; i++) {
                      printf("- %i: %08x\n", i, breakpoint[i]);
                  }
              }
              else if (buf[0] == 't')
              {
                  printf("reg_target value to watch (in hex, 0 to disable): ");
                  scanf("%x", &reg_target);
                  if (reg_target == 0) {
                      watch_reg = 0;
                      printf("reg_target unset\n");
                  } else {
                      watch_reg = 1;
                      printf("reg_target value: %x\n", reg_target);
                  }
              }
              else if (buf[0] == 'r')
              {
                  printf("search_string_read (enter to remove): ");
                  scanf("%s", search_string_read);
                  search_string_read_length = strlen(search_string_read);
                  if (search_string_read_length == 0) {
                      printf("search_string_read unset\n");
                  } else {
                      printf("search_string_read (len %i): %s\n",
                              search_string_read_length,
                              search_string_read);
                  }
              }
              else if (buf[0] == 'w')
              {
                  printf("search_string_write (enter to remove): ");
                  scanf("%s", search_string_write);
                  search_string_write_length = strlen(search_string_write);
                  if (search_string_write_length == 0) {
                      printf("search_string_write unset\n");
                  } else {
                      printf("search_string_write (len %i): %s\n",
                              search_string_write_length,
                              search_string_write);
                  }
              }
              else if (buf[0] == '1')
              {
                  printf("Address to watch byte: ");
                  scanf("%x", &addr);
                  int i;
                  for (i = 0; i < 4; i++) {
                      if (watch_byte[i] == 0) {
                          watch_byte[i] = addr;
                          break;
                      }
                  }
                  if (i == 4) {
                      printf("Only 4 byte watchpoints supported\n");
                  }
                  printf("Byte watchpoints:\n");
                  for (i = 0; i < 4; i++) {
                      printf("- %i: %08x\n", i, watch_byte[i]);
                  }
              }
              else if (buf[0] == '2')
              {
                  printf("Address to watch word: ");
                  scanf("%x", &addr);
                  int i;
                  for (i = 0; i < 4; i++) {
                      if (watch_word[i] == 0) {
                          watch_word[i] = addr;
                          break;
                      }
                  }
                  if (i == 4) {
                      printf("Only 4 word watchpoints supported\n");
                  }
                  printf("Word watchpoints:\n");
                  for (i = 0; i < 4; i++) {
                      printf("- %i: %08x\n", i, watch_word[i]);
                  }
              }
              else if (buf[0] == '4')
              {
                  printf("Address to watch dword: ");
                  scanf("%x", &addr);
                  int i;
                  for (i = 0; i < 4; i++) {
                      if (watch_dword[i] == 0) {
                          watch_dword[i] = addr;
                          break;
                      }
                  }
                  if (i == 4) {
                      printf("Only 4 dword watchpoints supported\n");
                  }
                  printf("Dword watchpoints:\n");
                  for (i = 0; i < 4; i++) {
                      printf("- %i: %08x\n", i, watch_dword[i]);
                  }
              }
              else if (buf[0] == 'D')
              {
                  printf("Remove breakpoint/watchpoint at: ");
                  scanf("%x", &addr);
                  int i;
                  for (i = 0; i < 4; i++) {
                      if (breakpoint[i] == addr) {
                          breakpoint[i] = 0;
                          break;
                      }
                  }
                  for (i = 0; i < 4; i++) {
                      if (watch_byte[i] == addr) {
                          watch_byte[i] = 0;
                          break;
                      }
                  }
                  for (i = 0; i < 4; i++) {
                      if (watch_word[i] == addr) {
                          watch_word[i] = 0;
                          break;
                      }
                  }
                  for (i = 0; i < 4; i++) {
                      if (watch_dword[i] == addr) {
                          watch_dword[i] = 0;
                          break;
                      }
                  }
                  printf("Breakpoints:\n");
                  for (i = 0; i < 4; i++) {
                      printf("- %i: %08x\n", i, breakpoint[i]);
                  }
                  printf("Byte watchpoints:\n");
                  for (i = 0; i < 4; i++) {
                      printf("- %i: %08x\n", i, watch_byte[i]);
                  }
                  printf("Word watchpoints:\n");
                  for (i = 0; i < 4; i++) {
                      printf("- %i: %08x\n", i, watch_word[i]);
                  }
                  printf("Dword watchpoints:\n");
                  for (i = 0; i < 4; i++) {
                      printf("- %i: %08x\n", i, watch_dword[i]);
                  }
              }
          }
      }

      BX_CPU_THIS_PTR prev_rip = RIP; // commit new RIP
      BX_INSTR_AFTER_EXECUTION(BX_CPU_ID, i);
      BX_CPU_THIS_PTR icount++;

      BX_SYNC_TIME_IF_SINGLE_PROCESSOR(0);

      // note instructions generating exceptions never reach this point
#if BX_DEBUGGER || BX_GDBSTUB
      if (dbg_instruction_epilog()) return;
#endif

      if (BX_CPU_THIS_PTR async_event) break;

      if (++i == last) {
        entry = getICacheEntry();
        i = entry->i;
        last = i + (entry->tlen);
      }
    }
#endif

    // clear stop trace magic indication that probably was set by repeat or branch32/64
    BX_CPU_THIS_PTR async_event &= ~BX_ASYNC_EVENT_STOP_TRACE;

  }  // while (1)
}

#if BX_SUPPORT_SMP

void BX_CPU_C::cpu_run_trace(void)
{
  if (setjmp(BX_CPU_THIS_PTR jmp_buf_env)) {
    // can get here only from exception function or VMEXIT
    BX_CPU_THIS_PTR icount++;
    return;
  }

  // check on events which occurred for previous instructions (traps)
  // and ones which are asynchronous to the CPU (hardware interrupts)
  if (BX_CPU_THIS_PTR async_event) {
    if (handleAsyncEvent()) {
      // If request to return to caller ASAP.
      return;
    }
  }

  bxICacheEntry_c *entry = getICacheEntry();
  bxInstruction_c *i = entry->i;

#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS
  // want to allow changing of the instruction inside instrumentation callback
  BX_INSTR_BEFORE_EXECUTION(BX_CPU_ID, i);
  RIP += i->ilen();
  // when handlers chaining is enabled this single call will execute entire trace
  BX_CPU_CALL_METHOD(i->execute1, (i)); // might iterate repeat instruction

  if (BX_CPU_THIS_PTR async_event) {
    // clear stop trace magic indication that probably was set by repeat or branch32/64
    BX_CPU_THIS_PTR async_event &= ~BX_ASYNC_EVENT_STOP_TRACE;
  }
#else
  bxInstruction_c *last = i + (entry->tlen);

  for(;;) {
    // want to allow changing of the instruction inside instrumentation callback
    BX_INSTR_BEFORE_EXECUTION(BX_CPU_ID, i);
    RIP += i->ilen();
    BX_CPU_CALL_METHOD(i->execute1, (i)); // might iterate repeat instruction
    BX_CPU_THIS_PTR prev_rip = RIP; // commit new RIP
    BX_INSTR_AFTER_EXECUTION(BX_CPU_ID, i);
    BX_CPU_THIS_PTR icount++;

    if (BX_CPU_THIS_PTR async_event) {
      // clear stop trace magic indication that probably was set by repeat or branch32/64
      BX_CPU_THIS_PTR async_event &= ~BX_ASYNC_EVENT_STOP_TRACE;
      break;
    }

    if (++i == last) break;
  }
#endif // BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS
}

#endif

bxICacheEntry_c* BX_CPU_C::getICacheEntry(void)
{
  bx_address eipBiased = RIP + BX_CPU_THIS_PTR eipPageBias;

  if (eipBiased >= BX_CPU_THIS_PTR eipPageWindowSize) {
    prefetch();
    eipBiased = RIP + BX_CPU_THIS_PTR eipPageBias;
  }

  INC_ICACHE_STAT(iCacheLookups);

  bx_phy_address pAddr = BX_CPU_THIS_PTR pAddrFetchPage + eipBiased;
  bxICacheEntry_c *entry = BX_CPU_THIS_PTR iCache.find_entry(pAddr, BX_CPU_THIS_PTR fetchModeMask);

  if (entry == NULL)
  {
    // iCache miss. No validated instruction with matching fetch parameters
    // is in the iCache.
    INC_ICACHE_STAT(iCacheMisses);
    entry = serveICacheMiss((Bit32u) eipBiased, pAddr);
  }

  return entry;
}

#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS && BX_ENABLE_TRACE_LINKING

// The function is called after taken branch instructions and tries to link the branch to the next trace
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::linkTrace(bxInstruction_c *i)
{
#if BX_SUPPORT_SMP
  if (BX_SMP_PROCESSORS > 1)
    return;
#endif

#define BX_HANDLERS_CHAINING_MAX_DEPTH 1000

  // do not allow extreme trace link depth / avoid host stack overflow
  // (could happen with badly compiled instruction handlers)
  static Bit32u linkDepth = 0;

  if (BX_CPU_THIS_PTR async_event || ++linkDepth > BX_HANDLERS_CHAINING_MAX_DEPTH) {
    linkDepth = 0;
    return;
  }

  Bit32u delta = (Bit32u) (BX_CPU_THIS_PTR icount - BX_CPU_THIS_PTR icount_last_sync);
  if(delta >= bx_pc_system.getNumCpuTicksLeftNextEvent()) {
    linkDepth = 0;
    return;
  }

  bxInstruction_c *next = i->getNextTrace(BX_CPU_THIS_PTR iCache.traceLinkTimeStamp);
  if (next) {
    BX_EXECUTE_INSTRUCTION(next);
    return;
  }

  bx_address eipBiased = RIP + BX_CPU_THIS_PTR eipPageBias;
  if (eipBiased >= BX_CPU_THIS_PTR eipPageWindowSize) {
    prefetch();
    eipBiased = RIP + BX_CPU_THIS_PTR eipPageBias;
  }

  INC_ICACHE_STAT(iCacheLookups);

  bx_phy_address pAddr = BX_CPU_THIS_PTR pAddrFetchPage + eipBiased;
  bxICacheEntry_c *entry = BX_CPU_THIS_PTR iCache.find_entry(pAddr, BX_CPU_THIS_PTR fetchModeMask);

  if (entry != NULL) // link traces - handle only hit cases
  {
    i->setNextTrace(entry->i, BX_CPU_THIS_PTR iCache.traceLinkTimeStamp);
    i = entry->i;
    BX_EXECUTE_INSTRUCTION(i);
  }
}

#endif

#define BX_REPEAT_TIME_UPDATE_INTERVAL (BX_MAX_TRACE_LENGTH-1)

void BX_CPP_AttrRegparmN(2) BX_CPU_C::repeat(bxInstruction_c *i, BxRepIterationPtr_tR execute)
{
  // non repeated instruction
  if (! i->repUsedL()) {
    BX_CPU_CALL_REP_ITERATION(execute, (i));
    return;
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = 0;
#endif

#if BX_SUPPORT_X86_64
  if (i->as64L()) {
    while(1) {
      if (RCX != 0) {
        BX_CPU_CALL_REP_ITERATION(execute, (i));
        BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
        RCX --;
      }
      if (RCX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_CPU_THIS_PTR icount++;

      BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
    }
  }
  else
#endif
  if (i->as32L()) {
    while(1) {
      if (ECX != 0) {
        BX_CPU_CALL_REP_ITERATION(execute, (i));
        BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
        RCX = ECX - 1;
      }
      if (ECX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_CPU_THIS_PTR icount++;

      BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
    }
  }
  else  // 16bit addrsize
  {
    while(1) {
      if (CX != 0) {
        BX_CPU_CALL_REP_ITERATION(execute, (i));
        BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
        CX --;
      }
      if (CX == 0) return;

#if BX_DEBUGGER == 0
      if (BX_CPU_THIS_PTR async_event)
#endif
        break; // exit always if debugger enabled

      BX_CPU_THIS_PTR icount++;

      BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
    }
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = 1;
#endif

  RIP = BX_CPU_THIS_PTR prev_rip; // repeat loop not done, restore RIP

  // assert magic async_event to stop trace execution
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::repeat_ZF(bxInstruction_c *i, BxRepIterationPtr_tR execute)
{
  unsigned rep = i->lockRepUsedValue();

  // non repeated instruction
  if (rep < 2) {
    BX_CPU_CALL_REP_ITERATION(execute, (i));
    return;
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = 0;
#endif

  if (rep == 3) { /* repeat prefix 0xF3 */
#if BX_SUPPORT_X86_64
    if (i->as64L()) {
      while(1) {
        if (RCX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          RCX --;
        }
        if (! get_ZF() || RCX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

        BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
      }
    }
    else
#endif
    if (i->as32L()) {
      while(1) {
        if (ECX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          RCX = ECX - 1;
        }
        if (! get_ZF() || ECX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

        BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
      }
    }
    else  // 16bit addrsize
    {
      while(1) {
        if (CX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          CX --;
        }
        if (! get_ZF() || CX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

        BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
      }
    }
  }
  else {          /* repeat prefix 0xF2 */
#if BX_SUPPORT_X86_64
    if (i->as64L()) {
      while(1) {
        if (RCX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          RCX --;
        }
        if (get_ZF() || RCX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

        BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
      }
    }
    else
#endif
    if (i->as32L()) {
      while(1) {
        if (ECX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          RCX = ECX - 1;
        }
        if (get_ZF() || ECX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

        BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
      }
    }
    else  // 16bit addrsize
    {
      while(1) {
        if (CX != 0) {
          BX_CPU_CALL_REP_ITERATION(execute, (i));
          BX_INSTR_REPEAT_ITERATION(BX_CPU_ID, i);
          CX --;
        }
        if (get_ZF() || CX == 0) return;

#if BX_DEBUGGER == 0
        if (BX_CPU_THIS_PTR async_event)
#endif
          break; // exit always if debugger enabled

        BX_CPU_THIS_PTR icount++;

        BX_SYNC_TIME_IF_SINGLE_PROCESSOR(BX_REPEAT_TIME_UPDATE_INTERVAL);
      }
    }
  }

#if BX_X86_DEBUGGER
  BX_CPU_THIS_PTR in_repeat = 1;
#endif

  RIP = BX_CPU_THIS_PTR prev_rip; // repeat loop not done, restore RIP

  // assert magic async_event to stop trace execution
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
}

// boundaries of consideration:
//
//  * physical memory boundary: 1024k (1Megabyte) (increments of...)
//  * A20 boundary:             1024k (1Megabyte)
//  * page boundary:            4k
//  * ROM boundary:             2k (dont care since we are only reading)
//  * segment boundary:         any

void BX_CPU_C::prefetch(void)
{
  bx_address laddr;
  unsigned pageOffset;

  INC_ICACHE_STAT(iCachePrefetch);

#if BX_SUPPORT_X86_64
  if (long64_mode()) {
    if (! IsCanonical(RIP)) {
      BX_ERROR(("prefetch: #GP(0): RIP crossed canonical boundary"));
      exception(BX_GP_EXCEPTION, 0);
    }

    // linear address is equal to RIP in 64-bit long mode
    pageOffset = PAGE_OFFSET(EIP);
    laddr = RIP;

    // Calculate RIP at the beginning of the page.
    BX_CPU_THIS_PTR eipPageBias = pageOffset - RIP;
    BX_CPU_THIS_PTR eipPageWindowSize = 4096;
  }
  else
#endif
  {

#if BX_CPU_LEVEL >= 5
    if (USER_PL && BX_CPU_THIS_PTR get_VIP() && BX_CPU_THIS_PTR get_VIF()) {
      if (BX_CPU_THIS_PTR cr4.get_PVI() | (v8086_mode() && BX_CPU_THIS_PTR cr4.get_VME())) {
        BX_ERROR(("prefetch: inconsistent VME state"));
        exception(BX_GP_EXCEPTION, 0);
      }
    }
#endif

    BX_CLEAR_64BIT_HIGH(BX_64BIT_REG_RIP); /* avoid 32-bit EIP wrap */
    laddr = get_laddr32(BX_SEG_REG_CS, EIP);
    pageOffset = PAGE_OFFSET(laddr);

    // Calculate RIP at the beginning of the page.
    BX_CPU_THIS_PTR eipPageBias = (bx_address) pageOffset - EIP;

    Bit32u limit = BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.limit_scaled;
    if (EIP > limit) {
      BX_ERROR(("prefetch: EIP [%08x] > CS.limit [%08x]", EIP, limit));
      exception(BX_GP_EXCEPTION, 0);
    }

    BX_CPU_THIS_PTR eipPageWindowSize = 4096;
    if (limit + BX_CPU_THIS_PTR eipPageBias < 4096) {
      BX_CPU_THIS_PTR eipPageWindowSize = (Bit32u)(limit + BX_CPU_THIS_PTR eipPageBias + 1);
    }
  }

#if BX_X86_DEBUGGER
  if (hwbreakpoint_check(laddr, BX_HWDebugInstruction, BX_HWDebugInstruction)) {
    signal_event(BX_EVENT_CODE_BREAKPOINT_ASSIST);
    if (! interrupts_inhibited(BX_INHIBIT_DEBUG)) {
       // The next instruction could already hit a code breakpoint but
       // async_event won't take effect immediatelly.
       // Check if the next executing instruction hits code breakpoint

       // check only if not fetching page cross instruction
       // this check is 32-bit wrap safe as well
       if (EIP == (Bit32u) BX_CPU_THIS_PTR prev_rip) {
         Bit32u dr6_bits = code_breakpoint_match(laddr);
         if (dr6_bits & BX_DEBUG_TRAP_HIT) {
           BX_ERROR(("#DB: x86 code breakpoint catched"));
           BX_CPU_THIS_PTR debug_trap |= dr6_bits;
           exception(BX_DB_EXCEPTION, 0);
         }
       }
    }
  }
  else {
    clear_event(BX_EVENT_CODE_BREAKPOINT_ASSIST);
  }
#endif

  BX_CPU_THIS_PTR clear_RF();

  bx_address lpf = LPFOf(laddr);
  bx_TLB_entry *tlbEntry = BX_TLB_ENTRY_OF(laddr, 0);
  Bit8u *fetchPtr = 0;

  if ((tlbEntry->lpf == lpf) && (tlbEntry->accessBits & (0x10 << USER_PL)) != 0) {
    BX_CPU_THIS_PTR pAddrFetchPage = tlbEntry->ppf;
    fetchPtr = (Bit8u*) tlbEntry->hostPageAddr;
  }
  else {
    bx_phy_address pAddr = translate_linear(tlbEntry, laddr, USER_PL, BX_EXECUTE);
    BX_CPU_THIS_PTR pAddrFetchPage = PPFOf(pAddr);
  }

  if (fetchPtr) {
    BX_CPU_THIS_PTR eipFetchPtr = fetchPtr;
  }
  else {
    BX_CPU_THIS_PTR eipFetchPtr = (const Bit8u*) getHostMemAddr(BX_CPU_THIS_PTR pAddrFetchPage, BX_EXECUTE);

    // Sanity checks
    if (! BX_CPU_THIS_PTR eipFetchPtr) {
      bx_phy_address pAddr = BX_CPU_THIS_PTR pAddrFetchPage + pageOffset;
      if (pAddr >= BX_MEM(0)->get_memory_len()) {
        BX_PANIC(("prefetch: running in bogus memory, pAddr=0x" FMT_PHY_ADDRX, pAddr));
      }
      else {
        BX_PANIC(("prefetch: getHostMemAddr vetoed direct read, pAddr=0x" FMT_PHY_ADDRX, pAddr));
      }
    }
  }
}

#if BX_DEBUGGER || BX_GDBSTUB
bx_bool BX_CPU_C::dbg_instruction_epilog(void)
{
#if BX_DEBUGGER
  bx_address debug_eip = RIP;
  Bit16u cs = BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.value;

  BX_CPU_THIS_PTR guard_found.cs  = cs;
  BX_CPU_THIS_PTR guard_found.eip = debug_eip;
  BX_CPU_THIS_PTR guard_found.laddr = get_laddr(BX_SEG_REG_CS, debug_eip);
  BX_CPU_THIS_PTR guard_found.code_32_64 = BX_CPU_THIS_PTR fetchModeMask;

  //
  // Take care of break point conditions generated during instruction execution
  //

  // Check if we hit read/write or time breakpoint
  if (BX_CPU_THIS_PTR break_point) {
    Bit64u tt = bx_pc_system.time_ticks();
    switch (BX_CPU_THIS_PTR break_point) {
    case BREAK_POINT_TIME:
      BX_INFO(("[" FMT_LL "d] Caught time breakpoint", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_TIME_BREAK_POINT;
      return(1); // on a breakpoint
    case BREAK_POINT_READ:
      BX_INFO(("[" FMT_LL "d] Caught read watch point", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_READ_WATCH_POINT;
      return(1); // on a breakpoint
    case BREAK_POINT_WRITE:
      BX_INFO(("[" FMT_LL "d] Caught write watch point", tt));
      BX_CPU_THIS_PTR stop_reason = STOP_WRITE_WATCH_POINT;
      return(1); // on a breakpoint
    default:
      BX_PANIC(("Weird break point condition"));
    }
  }

  if (BX_CPU_THIS_PTR magic_break) {
    BX_INFO(("[" FMT_LL "d] Stopped on MAGIC BREAKPOINT", bx_pc_system.time_ticks()));
    BX_CPU_THIS_PTR stop_reason = STOP_MAGIC_BREAK_POINT;
    return(1); // on a breakpoint
  }

  // see if debugger requesting icount guard
  if (bx_guard.guard_for & BX_DBG_GUARD_ICOUNT) {
    if (get_icount() >= BX_CPU_THIS_PTR guard_found.icount_max) {
      return(1);
    }
  }

  // convenient point to see if user requested debug break or typed Ctrl-C
  if (bx_guard.interrupt_requested) {
    return(1);
  }

  // support for 'show' command in debugger
  extern unsigned dbg_show_mask;
  if(dbg_show_mask) {
    int rv = bx_dbg_show_symbolic();
    if (rv) return(rv);
  }

  // Just committed an instruction, before fetching a new one
  // see if debugger is looking for iaddr breakpoint of any type
  if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_ALL) {
#if (BX_DBG_MAX_VIR_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_VIR) {
      for (unsigned n=0; n<bx_guard.iaddr.num_virtual; n++) {
        if (bx_guard.iaddr.vir[n].enabled &&
           (bx_guard.iaddr.vir[n].cs  == cs) &&
           (bx_guard.iaddr.vir[n].eip == debug_eip))
        {
          BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_VIR;
          BX_CPU_THIS_PTR guard_found.iaddr_index = n;
          return(1); // on a breakpoint
        }
      }
    }
#endif
#if (BX_DBG_MAX_LIN_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_LIN) {
      for (unsigned n=0; n<bx_guard.iaddr.num_linear; n++) {
        if (bx_guard.iaddr.lin[n].enabled &&
           (bx_guard.iaddr.lin[n].addr == BX_CPU_THIS_PTR guard_found.laddr))
        {
          BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_LIN;
          BX_CPU_THIS_PTR guard_found.iaddr_index = n;
          return(1); // on a breakpoint
        }
      }
    }
#endif
#if (BX_DBG_MAX_PHY_BPOINTS > 0)
    if (bx_guard.guard_for & BX_DBG_GUARD_IADDR_PHY) {
      bx_phy_address phy;
      bx_bool valid = dbg_xlate_linear2phy(BX_CPU_THIS_PTR guard_found.laddr, &phy);
      if (valid) {
        for (unsigned n=0; n<bx_guard.iaddr.num_physical; n++) {
          if (bx_guard.iaddr.phy[n].enabled && (bx_guard.iaddr.phy[n].addr == phy))
          {
            BX_CPU_THIS_PTR guard_found.guard_found = BX_DBG_GUARD_IADDR_PHY;
            BX_CPU_THIS_PTR guard_found.iaddr_index = n;
            return(1); // on a breakpoint
          }
        }
      }
    }
#endif
  }
#endif

#if BX_GDBSTUB
  if (bx_dbg.gdbstub_enabled) {
    unsigned reason = bx_gdbstub_check(EIP);
    if (reason != GDBSTUB_STOP_NO_REASON) return(1);
  }
#endif

  return(0);
}
#endif // BX_DEBUGGER || BX_GDBSTUB
