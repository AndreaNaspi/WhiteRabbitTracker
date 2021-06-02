/* ===================================================================== */
/* Define taint color                                                    */
/* ===================================================================== */
#define TAINT_COLOR_1 0x01
#define TAINT_COLOR_2 0x02
#define TAINT_COLOR_3 0x03
#define TAINT_COLOR_4 0x04
#define TAINT_COLOR_5 0x05
#define TAINT_COLOR_6 0x06
#define TAINT_COLOR_7 0x07
#define TAINT_COLOR_8 0x08

/* ============================================================================= */
/* Define macro to taint a register using thread_ctx_ptr and GPR from libdft     */
/* ============================================================================= */
#define TAINT_TAG_REG(ctx, taint_gpr, t0, t1, t2, t3) do { \
tag_t _tags[4] = {t0, t1, t2, t3}; \
thread_ctx_t *thread_ctx = (thread_ctx_t *)PIN_GetContextReg(ctx, thread_ctx_ptr); \
addTaintRegister(thread_ctx, taint_gpr, _tags, true); \
} while (0)

/* ===================================================================== */
/* Enable/disable tainting capabilities                                  */
/* ===================================================================== */
// Low-level instructions
#define TAINT_CPUID                  1
#define TAINT_RDTSC                  0
#define TAINT_IN                     0
#define TAINT_OBSIDIUM_DISK_DRIVE    0
// Windows syscalls
#define TAINT_NTCREATEFILE           0
#define TAINT_NTOPENKEY              0
#define TAINT_NTENUMERATEKEY         0
#define TAINT_NTQUERYVALUEKEY        0
#define TAINT_NTQIP_DEBUGFLAG        0
#define TAINT_NTQIP_DEBUGOBJECT      0
#define TAINT_NTQSI_PROCESSINFO      1
#define TAINT_NTQSI_MODULEINFO       1
#define TAINT_NTQSI_FIRMWAREINFO     0
#define TAINT_NTQSI_KERNELINFO       1
#define TAINT_NTQUERYATTRIBUTESFILE  1
#define TAINT_NTFINDWINDOW           0
// Function calls
#define TAINT_ISDEBUGGERPRESENT      0
#define TAINT_CHECKREMOTEDEBUGGER    0
#define TAINT_ENUMPROCESSES          0
#define TAINT_PROCESS32FIRSTNEXT     0
#define TAINT_GETDISKFREESPACE       0
#define TAINT_GLOBALMEMORYSTATUS     0
#define TAINT_GETSYSTEMINFO          0
#define TAINT_GETCURSORPOS           0
#define TAINT_GETMODULEFILENAME      0
#define TAINT_GETDEVICEDRIVERNAME    0
#define TAINT_GETADAPTERSINFO        1
#define TAINT_ENUMDISPLAYSETTINGS    1
#define TAINT_GETTICKCOUNT           0
#define TAINT_ICMPSENDECHO           0
#define TAINT_LOADLIBRARY            1
#define TAINT_GETUSERNAME            0
#define TAINT_FINDWINDOW             0