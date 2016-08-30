#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_proc.h"
#include "bcc_syms.h"
#include "vendor/tinyformat.hpp"

#include "catch.hpp"

#include "bpf_common.h"
#include "linux/bpf.h"
#include "../../src/libbpf.h"

TEST_CASE("test bpf", "[c_bpf]") {
  char *found = NULL;
  char error_msg [] = "R7 invalid mem access 'map_value_or_null'";
  void *mod = bpf_module_create_c("/root/bcc/tests/cc/test_bpf_error.c", 0, 0, 0);
  REQUIRE(mod);
  char log[EXT_LOG_BUF_SIZE];
  void *start = bpf_function_start(mod, "bridge_port");
  int size = bpf_function_size(mod, "bridge_port");
  char *license = bpf_module_license(mod);
  unsigned version = bpf_module_kern_version(mod);
  int i = bpf_prog_load(BPF_PROG_TYPE_SCHED_CLS, (const struct bpf_insn *) start, size, license, version, log, EXT_LOG_BUF_SIZE);
  found = strstr(log, error_msg);
  REQUIRE(found);
} 

