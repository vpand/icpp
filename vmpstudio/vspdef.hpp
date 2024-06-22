///////////////////////////////////VPAND.COM////////////////////////////////////
//                                                                             *
// VMPStudio PLUGIN HEADER FILE                                                *
//                                                                             *
// Copyright(C) 2022 VPAND.COM Team, ALL RIGHTS RESERVED.                      *
//                                                                             *
// Internet: yunyoo.cn vpand.com                                               *
//                                                                             *
// This code is distributed "as is", part of VMPStudio and without warranty of *
// any kind, expressed or implied, including, but not limited to warranty of   *
// fitness for any particular purpose. In no event will VMPStudio be liable to *
// you for any special, incidental, indirect, consequential or any other       *
// damages caused by the use, misuse, or the inability to use of this code,    *
// including anylost profits or lost savings,even if VMPStudio has been advised*
// of the possibility of such damages.                                         *
//                                                                             *
///////////////////////////////////////*////////////////////////////////////////
#ifndef __VSPDEF_H__
#define __VSPDEF_H__

#define __VSP_VERSION__ "1.0.0"
#define __VSP_CDECL__ extern "C"

// windows definition
#if defined(_WIN32) || defined(_WIN64)

#define __VSP_EXPORT__ __declspec(dllexport)

typedef long long vspint;

// macOS definition
#else

#define __VSP_EXPORT__ __attribute__((visibility("default")))

typedef long vspint;

#endif // end of _WIN

// c api definition
#define __VSP_API__ __VSP_CDECL__ __VSP_EXPORT__

// api entry error code definition
enum vsp_error_t {
  vsp_err_ok,         // success
  vsp_err_failed,     // failed
  vsp_err_canceled,   // canceled
  vsp_err_param,      // bad parameter
  vsp_err_notfound,   // cannot find something
  vsp_err_io,         // io issue
  vsp_err_thread,     // thread issue, some api must run at ui thread
  vsp_err_oor,        // out of range
  vsp_err_oom,        // out of memory
  vsp_err_auth,       // license issue
  vsp_err_permission, // permission issue
  vsp_err_unsupport,  // unsupport some action
  vsp_err_unimpl,     // unimplement some action
  vsp_err_softbug,    // software bug assertion
  vsp_err_continue,   // for traverser
  vsp_err_break,      // for traverser
};

// event definition
#define decl_event(n, desc) vsp_event_##n
#define decl_event_input(n, input, desc) decl_event(n, desc)
#define decl_event_result(n, result, desc) decl_event(n, desc)
#define decl_event_io(n, input, result, desc) decl_event(n, desc)
enum vsp_event_t {
  // event with no Input/Output
  decl_event(loaded, "after loaded this plugin"),
  decl_event(pre_unload, "before unload this plugin"),
  decl_event(main_menu, "user triggered MainMenu/Plugin/ThisPlugin"),
  decl_event(module_analyzed, "tell plugin finished analyzing an file module"),
  decl_event(module_closed, "tell plugin closed the module"),
  decl_event(sample_initialized,
             "tell plugin a new uvm sample session initialized"),

  // event for Result
  decl_event_result(version, str_const, "ask this plugin for its sdk version"),
  decl_event_result(menuname, str_const,
                    "ask this plugin for its plugin menu name"),
  // ptr.p0 should be vsp's self version string
  // ptr.p1 should be vsp's description
  decl_event_result(vspinfo, ptr,
                    "ask this plugin for its self version and description"),

  // event with Input for Result
  // currently nothing

  /*
   * added by vsp v1.0.x
   */
  //...
  // Tell me, what the extra event do you want ?
};

enum vsp_file_t {
  vsp_file_unknown,
  vsp_file_macho,
  vsp_file_elf,
  vsp_file_pe,
};

enum vsp_arch_t {
  vsp_arch_unsupport,
  vsp_arch_armv5te,
  vsp_arch_arm,
  vsp_arch_arm64,
  vsp_arch_x86,
  vsp_arch_x64,
};

// bytes definition
struct vsp_bytes_t {
  char *ptr;
  vspint len;
};

// pair definition
struct vsp_pair_t {
  void *p0;
  void *p1;
};

// module definition
struct vsp_module_t {
  const char *path;
  const char *buff;
  vspint size;
  vspint imagebase;
};

// function definition
struct vsp_func_t {
  const char *name;
  // rva to its parent module
  vspint start;
  vspint end;
};

// sample database definition
struct vsp_sdb_t {
  vspint rtbase;      // trace runtime base
  vspint totaltracks; // total uvmse trace tracks
  vspint curtrack;    // current selected trace track
};

// api definition
struct vsp_api_t {
  /*
   * added by vsp v1.0.0
   */
  // get current VMPStudio's version
  const char *(*version)();
  // logger
  void (*log)(const char *msg);
  // logger for status bar
  void (*logStatus)(const char *msg);
  // make cpu window goto the specified address
  void (*gotoCPUAddress)(vspint addr);
  // make uvmse trace window goto the specified address
  void (*gotoTraceAddress)(vspint addr);
  // get the loaded module information
  vsp_error_t (*getModule)(vsp_module_t *module);
  // iterate module functions
  vsp_error_t (*travelFunc)(void *context,
                            vsp_error_t (*handler)(void *context,
                                                   const vsp_func_t *func));
  // check whether has loaded module
  vspint (*hasModule)();
  // read module bytes with file offset
  vsp_error_t (*readBytesFoff)(vspint foff, void *buff, vspint size);
  // read module bytes with address
  vsp_error_t (*readBytesAddr)(vspint addr, void *buff, vspint size);
  // make dump window goto the specified address, 0-4
  vsp_error_t (*gotoDumpAddress)(vspint addr, vspint index);
  // get configuration
  vsp_error_t (*getIntConfig)(const char *sect, const char *key, vspint *value);
  vsp_error_t (*getConfig)(const char *sect, const char *key, char *cfg,
                           vspint cfgsize);
  // set configuration
  vsp_error_t (*setIntConfig)(const char *sect, const char *key, vspint value);
  vsp_error_t (*setConfig)(const char *sect, const char *key, const char *cfg);
  // ask user to input a string
  vsp_error_t (*inputString)(const char *title, char *text, vspint size);
  // ask user to input an integer
  vsp_error_t (*inputInteger)(const char *title, vspint *value);
  // ask user to select a path
  vsp_error_t (*inputPath)(char *path, vspint size, vspint isdir,
                           vspint isopen);
  // disassemble an opcode
  vsp_error_t (*disassemble)(const void *opcode, char *asmcode, vspint asmsize);
  // assemble an asm instruction
  vsp_error_t (*assemble)(const char *asmcode, void *opcode);
  // set uvm breakpoint at the specified address
  vsp_error_t (*setUVMBreakpoint)(vspint addr);
  // unset uvm breakpoint at the specified address
  vsp_error_t (*unsetUVMBreakpoint)(vspint addr);
  // get current sdb information
  vsp_error_t (*getSampleDatabase)(vsp_sdb_t *sdb);
  // get trace track pc indexs
  vsp_error_t (*getTrackIndexs)(vspint i, const vspint **indexs, vspint *size);
  // get register record handle and count at address
  vsp_error_t (*getRecordInfo)(vspint addr, const void **handle, vspint *size);
  // pickup current register value like x0-x29,lr,sp,pc
  vsp_error_t (*getRegister)(const void *handle, vspint index,
                             const char *regname, vspint *regvalue);
  // pickup current register value with register index
  // arm [0-14]
  // arm64 [0-30]
  // x86/x86_64 [0-15]
  vsp_error_t (*getRegisterWithIndex)(const void *handle, vspint index,
                                      vspint regidx, vspint *regvalue);
  // pickup current address runtime memory page
  vsp_error_t (*getMemoryPage)(vspint addr, vspint *pageaddr,
                               const char **pagebuff, vspint *pagesize);
  // execute an remote shell command
  vsp_error_t (*command)(const char *cmd);
  vsp_error_t (*commandResult)(const char *cmd, char *result, vspint size);
  // register plugin's command handler, return its id for unregister
  vspint (*registerCommander)(const char *name,
                              bool (*handler)(const char *cmd));
  // unregister command handler, idval is returned by registerCommander
  void (*unregisterCommander)(vspint idval);
  // attach to the pid for the module dependent process
  void (*attach)(vspint pid);
  // detach from current sampleee
  void (*detach)();
  // get the current module file type
  vsp_file_t (*curFileType)();
  // get the current module machine arch type
  vsp_arch_t (*curArchType)();
  // get the current commander
  vspint (*curCommander)();

  //...
  // Tell me, what the extra api do you want ?
};

// main entry input vars definition
struct vsp_input_t {
  // 8 bytes integer input
  vspint val;

  // string input
  const char *str;

  // binary buffer input
  vsp_bytes_t buf;

  // depend on event
  const void *ptr;
};

// main entry output result
union vsp_result_t {
  // 8 bytes integer result
  vspint val;

  // string result
  const char *str_const;
  char *str_dyn; // will free this buffer after use

  // binary buffer result
  vsp_bytes_t buf_const;
  vsp_bytes_t buf_dyn; // will free this buffer after use

  // depend on event
  vsp_pair_t ptr;
};

// payload for plugin main entry difinition
struct vsp_payload_t {
  // constants
  const vsp_api_t *api;   // all the VMPStudio's user api
  vspint consts_dummy[8]; // for future use

  // input vars
  vsp_event_t event;     // why call this plugin main entry
  vsp_input_t input;     // input vars for plugin
  vspint input_dummy[8]; // for future use

  // output result
  vsp_result_t result;
  vspint dummy[8]; // for future use
};

// a valid VMPStudio plugin must implement this function
__VSP_API__ vsp_error_t vsp_main(vsp_payload_t *vsp);

#endif // end of __VSPDEF_H__
