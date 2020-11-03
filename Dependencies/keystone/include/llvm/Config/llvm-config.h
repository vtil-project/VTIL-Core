#ifdef _WIN32
#define LLVM_ON_WIN32
#else
#define LLVM_ON_UNIX

// Just randomly enabled things until it works (compiles fine on both Ubuntu and OS X)
//#define HAVE__CHSIZE_S 1
//#define HAVE_DECL_ARC4RANDOM 1
#define HAVE_DIRENT_H 1
#define HAVE_DLFCN_H 1
#define HAVE_FCNTL_H 1
//#define HAVE_GETPAGESIZE 1
//#define HAVE_ISATTY 1
//#define HAVE_LIBPSAPI 1
//#define HAVE_LIBSHELL32 1
//#define HAVE_MACH_MACH_H 1
//#define HAVE_MALLCTL 1
//#define HAVE_MALLINFO 1
//#define HAVE_MALLOC_H 1
//#define HAVE_MALLOC_MALLOC_H 1
//#define HAVE_MALLOC_ZONE_STATISTICS 1
//#define HAVE_MMAP_ANONYMOUS 1
//#define HAVE_NDIR_H 1
//#define HAVE_PREAD 1
//#define HAVE_SBRK 1
//#define HAVE_SETRLIMIT 1
//#define HAVE_SIGNAL_H 1
#define HAVE_STDINT_H 1
//#define HAVE_SYS_DIR_H 1
//#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_MMAN_H 1
//#define HAVE_SYS_NDIR_H 1
#define HAVE_SYS_PARAM_H 1
//#define HAVE_SYS_RESOURCE_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1
//#define HAVE_SYS_UIO_H 1
//#define HAVE_SYSCONF 1
//#define HAVE_TERMINFO 1
//#define HAVE_TERMIOS_H 1
#define HAVE_UNISTD_H 1
//#define HAVE_WRITEV 1
#endif // _WIN32