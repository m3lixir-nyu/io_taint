/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "taint2/taint2.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
#include "taint2/taint2_ext.h"

bool init_plugin(void*);
void uninit_plugin(void*);
}

static target_ulong START_ADDR;
static target_ulong END_ADDR;
static target_ulong EXIT_ADDR;
static uint32_t LABEL = 0;

static bool addr_in_range(target_ulong addr)
{
    if (START_ADDR <= addr && addr <= END_ADDR) {
	return true;
    }
    return false;
}

static int before_block_exec_callback(CPUState* env, TranslationBlock* tb)
{
    if (EXIT_ADDR && tb->pc == EXIT_ADDR) {
        panda_end_replay();
    }

    Panda__IOTaint* io = (Panda__IOTaint*)malloc(sizeof(Panda__IOTaint));
    *io = PANDA__IOTAINT__INIT;
    io->tb_pc = tb->pc;
    io->tb_cs_base = tb->cs_base;
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.io_taint = io;
    pandalog_write_entry(&ple);
    free(io);
    return 0;
}

static int phys_mem_before_read_callback(CPUState* env, target_ulong pc, target_ulong addr, target_ulong size)
{
    if (!addr_in_range(addr)) {
	return 0;
    }

    printf("[PHYS MEM] READ   0x" TARGET_FMT_lx "  ", addr);
    return 0;
}

static int phys_mem_after_read_callback(CPUState* env, target_ulong pc, target_ulong addr, target_ulong size, void* buf)
{
    if (!addr_in_range(addr)) {
	return 0;
    }

    if (!taint2_enabled()) {
	taint2_enable_taint();
    }

    taint2_label_ram(addr, LABEL++);

    // print hex
    for (size_t i = 0; i < size; ++i) {
	printf("%02x ", ((unsigned char*)buf)[i]);
    }

    printf(" ");

    // print ascii
    for (size_t i = 0; i < size; ++i) {
	printf("%c ", ((unsigned char*)buf)[i]);
    }

    printf("\n");
    printf("[PHYS MEM] Labeling address 0x" TARGET_FMT_lx " with label %u\n", addr, LABEL - 1);
    return 0;
}

static int phys_mem_before_write_callback(CPUState* env, target_ulong pc, target_ulong addr, target_ulong size, void* buf)
{
    if (!addr_in_range(addr)) {
	return 0;
    }

    printf("[PHYS MEM] WRITE  0x" TARGET_FMT_lx "  ", addr);
    return 0;
}

static int phys_mem_after_write_callback(CPUState* env, target_ulong pc, target_ulong addr, target_ulong size, void* buf)
{
    if (!addr_in_range(addr)) {
	return 0;
    }

    // print hex
    for (size_t i = 0; i < size; ++i) {
	printf("%02x ", ((unsigned char*)buf)[i]);
    }

    printf(" ");

    // print ascii
    for (size_t i = 0; i < size; ++i) {
	if (isprint(((unsigned char*)buf)[i])) {
	    printf("%c ", ((unsigned char*)buf)[i]);
	} else {
	    printf(".");
	}
    }

    printf("\n");
    return 0;
}

bool init_plugin(void* self)
{
    panda_enable_memcb();
    panda_cb pcb;

    panda_arg_list* args = panda_get_args("io_taint");
    START_ADDR = panda_parse_ulong(args, "start_addr", 0);
    END_ADDR = panda_parse_ulong(args, "end_addr", 0);
    EXIT_ADDR = panda_parse_ulong(args, "exit_addr", 0);
    panda_free_args(args);

    panda_require("taint2");
    assert(init_taint2_api());

    pcb.before_block_exec = before_block_exec_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.phys_mem_before_read = phys_mem_before_read_callback;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);

    pcb.phys_mem_after_read = phys_mem_after_read_callback;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, pcb);

    pcb.phys_mem_before_write = phys_mem_before_write_callback;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);

    pcb.phys_mem_after_write = phys_mem_after_write_callback;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, pcb);

    return true;
}

void uninit_plugin(void* self) {}
