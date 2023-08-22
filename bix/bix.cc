/*//------------------------------------------------------------
the "{entryname}.bix" config file must be placed alongside the "bix stub executable",
in case the "bix stub executable" is called throught a symlink the same applies the
"{entryname}.bix" config file should be placed alongside the linked-to
"bix stub executable" and not the symlink itself

example without symlink:
/bip/nginx/nginx                  ("bix stub executable" renamed to "nginx")
/bip/nginx/nginx.bix              ("{entryname}.bix" config file)
/bip/nginx/approot/usr/sbin/nginx  (final user executable)

example with symlink:
/bip/nginx/nginx                  (symlink to: ./bix/bix)
/bip/nginx/bix/bix                ("bix stub executable")
/bip/nginx/bix/nginx.bix          ("{entryname}.bix" config file)
/bip/nginx/approot/usr/sbin/nginx  (final user executable)

example "{entryname}.bix" config file content:

# final execution mode: ld | ld_env | ns
mode = ld_env

# ld binary and lib paths to use in ld or ld_env mode
ld = {{BIX_BD}}/approot/lib64/ld-linux-x86-64.so.2
ld_libpaths = {{BIX_BD}}/approot/lib64:{{BIX_BD}}/approot/lib

# ns parameters to use in ns mode
ns_newroot = {{BIX_BD}}/approot
# ns tmpdir will be automatically created and populated
ns_tmpdir = {{BIX_BD}}/.bix_ns

# final user executable relative or absolute path/cmd
cmd = {{BIX_BD}}/approot/usr/sbin/nginx
//------------------------------------------------------------*/

#define _ALL_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>
#include <string.h>
#include <stdarg.h>
#include <sched.h>
#include <crypt.h>
#include <dirent.h>
#include <glob.h>
#include <regex.h> //posix/musl(TRE engine) regex

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
//#include <sys/capability.h> //not avalilable in musl libc

#include <linux/fs.h>

extern char **environ;

//------------------------------------------------------------

//avoid ~100kb of garbage added by the c++ compiler
extern "C" char* __cxa_demangle(const char* mangled_name, char* buf, size_t* n, int* status) {
  if (status) *status = -1;
  return nullptr;
}

enum {
  XLOG_ERROR,
  XLOG_WARN,
  XLOG_INFO,
  XLOG_DEBUG
};
int xlog_level = XLOG_ERROR;
#define XLOG(level, fmt, ...) do { if (xlog_level==-1 || level <= xlog_level) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#define XLOG_ISLVL(level) (xlog_level==-1 || level <= xlog_level)
//#define NOOP(x) do {} while(0)

//#define X_ARR_RESIZE(arr_p, arr_newcap) do { arr_p = realloc(arr_p,sizeof(arr_p[0])*(arr_newcap)); } while (0)

//auto hash = x_realloc<char*>(nullptr,128);
//char* sl_value = x_realloc(sl_value,sl_size);
template<typename T,typename TS>
T x_realloc(T arr_p, TS arr_newcap) {
  return (T) realloc(arr_p,sizeof(arr_p[0])*arr_newcap);
  //return nullptr;
}

//Jonathan Blow C++ defer (MIT)
//https://gist.github.com/andrewrk/ffb272748448174e6cdb4958dae9f3d8#file-microsoft_craziness-h-L121
//Usage: defer { free(wildcard_name); };
// Defer macro/thing.
#define CONCAT_INTERNAL(x,y) x##y
#define CONCAT(x,y) CONCAT_INTERNAL(x,y)
template<typename T>
struct ExitScope {
    T lambda;
    ExitScope(T lambda):lambda(lambda){}
    ~ExitScope(){lambda();}
    ExitScope(const ExitScope&);
  private:
    ExitScope& operator =(const ExitScope&);
};
class ExitScopeHelp {
  public:
    template<typename T>
        ExitScope<T> operator+(T t){ return t;}
};
#define defer const auto& CONCAT(defer__, __LINE__) = ExitScopeHelp() + [&]()

int x_mkpath(char *dir, mode_t mode) {
  //XLOG(XLOG_ERROR,"x_mkpath: %s\n", dir);
  //struct stat sb;
  if (!dir) {
    //errno = EINVAL;
    return -1;
  }
  //if (!stat(dir, &sb)) return 0;
  int ret1 = mkdir(dir, mode);
  if(ret1==EEXIST) return ret1;
  //int len = strlen(dir);
  char* curr_pos = dir;
  int n = 0;
  while(1) {
    curr_pos = strchr(curr_pos,'/');
    if(!curr_pos) break;
    if(curr_pos==dir) {
      curr_pos += 1;
      continue;
    }
    *curr_pos = 0;
    int ret = mkdir(dir, mode);
    //XLOG(XLOG_ERROR,"mkdir: %s ret: %d errno: %d n: %d\n", dir, ret, errno, n);
    if(ret && errno!=EEXIST) return ret;
    n += 1;
    *curr_pos = '/';
    curr_pos += 1;
  }
  int ret = mkdir(dir, mode);
  //XLOG(XLOG_ERROR,"mkdir END: %s ret: %d errno: %d n: %d\n", dir, ret, errno, n);
  if(ret && errno!=EEXIST) return ret;
  return 0;
}

char* x_readlink(char* symlink_path) {
  struct stat sl_stat = {};
  int ls_err = lstat(symlink_path,&sl_stat);
  if(ls_err) return NULL;
  int is_symlink = S_ISLNK(sl_stat.st_mode);
  if(!is_symlink) return NULL;
  int sl_size = sl_stat.st_size + 1;
  //char* sl_value = malloc(sl_size);
  char* sl_value = x_realloc(sl_value,sl_size);
  
  int rlbytes = readlink(symlink_path, sl_value, sl_size);
  /* If the return value was equal to the buffer size, then the
  the link target was larger than expected (perhaps because the
  target was changed between the call to lstat() and the call to
  readlink()). Warn the user that the returned target may have
  been truncated. */
  if(rlbytes==sl_size) {
    free(sl_value);
    return NULL;
  }
  sl_value[rlbytes] = 0; //readlink() does not put terminating null byte
  return sl_value;
}

char* x_hash(char* data) {
  //char* hash = malloc(128);
  auto hash = x_realloc<char*>(nullptr,128);
  crypt_r(data,"$1$",(struct crypt_data *)hash); //$1$ MD5
  int len = strlen(hash);
  hash = (char*) memmove(hash,hash+4,len-4+1); //skip $1$$ prefix in hash output
  for(int i=0; i<len; i++){
    if(hash[i] == '.'){
      hash[i] = '-';
    }
    else if(hash[i] == '/'){
      hash[i] = '_';
    }
  }
  return hash;
}

void x_rtrim(char* s, size_t sl, char* tc) {
  if(!s) return;
  if(!tc) return;
  if(sl==0) sl = strlen(s);
  char* p = s + sl;
  //char* tc = "\r\n";
  while(1) {
    p -= 1;
    if(p==s) break;
    if(*p == 0) continue;
    if(!strchr(tc,*p)) break;
    *p = 0;
  }
}

//x_str_expenvvars("{{USER}} A {{SHELL}} B {{LANG}} C");
//x_str_expenvvars("X {{USER}} A {{SHELL}} B {{LANG}}");
char* x_str_expenvvars(char* str) {
  int rxret, wret, rret;
  regex_t regex;
  regmatch_t m[2];
  //char* rx = "\\{\\{([^\\}]+)\\}\\}";
  auto rx = R"|(\{\{([^\}]+)\}\})|";
  rxret = regcomp(&regex,rx,REG_EXTENDED);
  char* start = str;
  int last_eo = 0;
  int sbfd = memfd_create("x_str_expenvvars",0);
  while(1) {
    int rxret = regexec(&regex, start, 2, m, 0);
    if(rxret == REG_NOMATCH) {
      wret = write(sbfd,start,strlen(start));
      break;
    }
    char* name = strndup(start+m[1].rm_so, m[1].rm_eo-m[1].rm_so);
    char* envval = getenv(name);
    free(name);
    wret = write(sbfd,start,m[0].rm_so);
    wret = write(sbfd,envval,strlen(envval));
    //printf("env %s = %s %d\n", name, envval, wret);
    start += m[0].rm_eo;
  }
  regfree(&regex);
  int size = lseek(sbfd, 0, SEEK_CUR);
  //char* ret = malloc(size+1);
  auto ret = x_realloc<char*>(nullptr,size+1);
  lseek(sbfd, 0, SEEK_SET);
  rret = read(sbfd,ret,size);
  //printf("size: %d rret: %d\n", size, rret);
  ret[size] = 0;
  close(sbfd);
  //printf("ret |%s|\n", ret);
  return ret;
}

char** x_cfg_loadfile(char *config_path) {
  //load .ini like conf file
  FILE *fp = fopen(config_path, "r");
  if (!fp) {
    //perror(config_path);
    return NULL;
  }
  defer {
    fclose(fp);
  };
  
  char* curline;
  size_t cursize;
  ssize_t curlen;
  
  regex_t regex;
  regmatch_t m[4];
  //musl libc only regex, but anyway un-greedy(+? *?) does not fully work
  //on the right side of the matches, so x_rtrim() call is required for each match see below
  //char* rx2 = "\\s*(#)?\\s*([^=]+?)\\s*=\\s*(.+?)\\s*";
  auto rx = R"|(\s*(#)?\s*([^=]+?)\s*=\s*(.+?)\s*)|";
  regcomp(&regex,rx,REG_EXTENDED);
  //perror(rx);
  //perror(rx2);
  defer {
    regfree(&regex);
  };

  int ret_size = 0;
  char** ret = NULL; //realloc(ret,sizeof(ret)*(size_curr+size_incr));
  int pos = 0;

  while(1) {
    curline = NULL;
    cursize = 0;
    curlen = getline(&curline, &cursize, fp);
    defer {
      free(curline);
    };
    if(curlen < 0) {
      //printf("curlen<0\n");
      //free(curline);
      break;
    }
    if(curlen==0) {
      //printf("curlen==0\n");
      //free(curline);
      continue;
    }
    
    //trim \r \n at the end of the line
    x_rtrim(curline, curlen, "\r\n");
    //printf("line: %s\n", curline);

    //use regex to parse the line
    int rxret = regexec(&regex, curline, 4, m, 0);
    if(rxret == REG_NOMATCH) {
      //printf("REG_NOMATCH\n");
      continue;
    }

    //comment line matched, skip
    if(m[1].rm_so != -1) {
      //printf("comment line, skip\n");
      continue;
    }

    //if no key and val match, skip
    if(m[2].rm_so == -1 || m[3].rm_so == -1) {
      //printf("no m_key or m_val, skip\n");
      continue;
    }

    //extract and trim rx key and val matches
    char* m_key = strndup(curline+m[2].rm_so, m[2].rm_eo-m[2].rm_so);
    x_rtrim(m_key, 0, " \r\n\t");
    //printf("m_key: >%s<\n", m_key);
    char* m_val = strndup(curline+m[3].rm_so, m[3].rm_eo-m[3].rm_so);
    x_rtrim(m_val, 0, " \r\n\t");
    //printf("m_val: >%s<\n", m_val);

    ret_size += 2;
    ret = x_realloc(ret,ret_size);
    ret[pos++] = m_key;
    ret[pos++] = m_val;

    if(feof(fp)) {
      //printf("feof\n");
      break;
    }
  }

  ret_size += 1;
  ret = x_realloc(ret,ret_size);
  ret[pos++] = NULL;

  return ret;
}

//x_memfd_execve("/proc/self/exe",argv,environ)
void x_memfd_execve(char *pathname,char **argv,char **envp) {
  int binfd = open(pathname, O_RDONLY | O_CLOEXEC);
  struct stat binfd_stat = {};
  fstat(binfd, &binfd_stat);
  char* memkey = NULL;
  asprintf(&memkey,"x_memexecve:%s",pathname);
  int memfd = memfd_create(memkey, MFD_CLOEXEC);
  int written = sendfile(memfd, binfd, 0, binfd_stat.st_size);
  //perror("X");
  //XLOG(XLOG_INFO,"arg2: %d %d %d %d\n",binfd, memfd, binfd_stat.st_size,written);
  close(binfd);
  //char** parg2 = &argv[0];
  //do {
  //  if(!parg2[0]) break;
  //  XLOG(XLOG_INFO,"arg2: %s\n",parg2[0]);
  //  parg2 += 1;
  //} while(1);
  fexecve(memfd, argv, envp);
  //perror("X");
}

int x_ns_prepare(char* newroot,char* mount_tmp_dir) {
  char* approot_path = newroot;
  char* mount_files_dir = mount_tmp_dir;

  int mketd = x_mkpath(mount_files_dir,0222);
  if(mketd) {
    XLOG(XLOG_ERROR,"mkpath mount_tmp_dir: %s %s\n",mount_tmp_dir,strerror(errno));
    return 1;
  }

  //get current process euid/egid
  uid_t euid = geteuid();
  gid_t egid = getegid();

  //unshare current process
  XLOG(XLOG_INFO,"unshare\n");
  int proc_has_cap_sys_admin = 1;
  int un_flags = CLONE_NEWNS;
  //int is_root = euid == 0;
  //if(!is_root) un_flags |= CLONE_NEWUSER;
  int unret = unshare(un_flags);
  //we have no CAP_SYS_ADMIN, retry unshare with CLONE_NEWUSER
  if(unret==-1) {
    proc_has_cap_sys_admin = 0;
    un_flags |= CLONE_NEWUSER;
    unret = unshare(un_flags);
  }

  //map current uid/gid to root is we are not already root
  if(!proc_has_cap_sys_admin) {
    XLOG(XLOG_INFO,"map_user\n");
    // writing "deny" to setgroups or the fllowing writes to uid_map and gid_map will fail see user_namespaces(7) for more documentation
    int fd_setgroups = open("/proc/self/setgroups", O_WRONLY);
    if (fd_setgroups > 0) {
      write(fd_setgroups, "deny", 4);
      close(fd_setgroups);
    }
    int fd_uid_map = open("/proc/self/uid_map", O_WRONLY);
    if (fd_uid_map > 0) {
      char* map_data = NULL;
      asprintf(&map_data,"0 %d 1",euid);
      write(fd_uid_map, map_data, strlen(map_data));
      close(fd_uid_map);
    }
    int fd_gid_map = open("/proc/self/gid_map", O_WRONLY);
    if (fd_gid_map > 0) {
      char* map_data = NULL;
      asprintf(&map_data,"0 %d 1",egid);
      write(fd_gid_map, map_data, strlen(map_data));
      close(fd_gid_map);
    }
  }

  //make process root fs recursively (MS_REC) private (MS_PRIVATE)
  XLOG(XLOG_INFO,"root_make_private\n");
  mount("none","/",NULL,MS_REC|MS_PRIVATE,0);

  //map dirs in approot to the new filesystem namespace
  struct dirent **diritems;
  int diritems_num = 0;
  //dirent_num = scandirat(app_root_dir, &items, NULL, NULL); //no wrapper in musl libc use scandir()
  diritems_num = scandir(approot_path, &diritems, NULL, NULL);
  defer {
    int i = 0;
    while(1) {
      if(i>=diritems_num) break;
      free(diritems[i]);
      i += 1;
    }
    free(diritems);
  };
  auto bm_s = x_realloc<char**>(nullptr,diritems_num);
  auto bm_t = x_realloc<char**>(nullptr,diritems_num);
  defer {
    free(bm_s);
    free(bm_t);
  };

  XLOG(XLOG_INFO,"num approot dirs: %d\n",diritems_num);

  int currdir_idx = 0;

  //1 first cycle on newroot items to prepare overlayfs
  currdir_idx = 0;
  while(1) {
    if(currdir_idx>=diritems_num) break;
    struct dirent* diritem = diritems[currdir_idx];
    
    char* dirname = diritem->d_name;
    //skip hidden dirs and . and ..
    if(dirname[0]=='.') {
      currdir_idx += 1;
      continue;
    }
    
    XLOG(XLOG_INFO,"c1 dir: %s\n",dirname);

    //prepare overlays mount paths
    char* mount_ovfs_lowerdir = NULL;
    char* mount_ovfs_upperdir = NULL;
    char* mount_ovfs_merged = NULL;
    char* mount_ovfs_work = NULL;
    char* mount_ovfs_options = NULL;
    char* mount_ovfs_target = NULL;
    
    //lowerdir=/lib,upperdir={TRR}/approot/lib,workdir={TRR}/ofs/lib.work
    asprintf(&mount_ovfs_merged,"%s/%s.merged",mount_files_dir,dirname);
    asprintf(&mount_ovfs_work,"%s/%s.work",mount_files_dir,dirname);
    int mke2 = x_mkpath(mount_ovfs_merged,0222);
    if(mke2) {
      XLOG(XLOG_ERROR,"mkpath mount_ovfs_merged: %s %s\n",mount_ovfs_merged,strerror(errno));
      return 1;
    }
    int mke3 = x_mkpath(mount_ovfs_work,0222);
    if(mke3) {
      XLOG(XLOG_ERROR,"mkpath mount_ovfs_work: %s %s\n",mount_ovfs_work,strerror(errno));
      return 1;
    }
    asprintf(&mount_ovfs_upperdir,"%s/%s",approot_path,dirname);
    asprintf(&mount_ovfs_lowerdir,"/%s",dirname);
    asprintf(&mount_ovfs_options,"lowerdir=%s,upperdir=%s,workdir=%s",
      mount_ovfs_lowerdir,
      mount_ovfs_upperdir,
      mount_ovfs_work
    );
    mount_ovfs_target = mount_ovfs_merged;

    //prepare bind mount paths
    char* mount_bind_target = NULL;
    char* mount_bind_source = NULL;
    mount_bind_target = mount_ovfs_lowerdir;
    mount_bind_source = mount_ovfs_merged;

    //overlayfs mount    
    XLOG(XLOG_INFO,"mount_overlayfs target: %s options: %s\n",mount_ovfs_target,mount_ovfs_options);
    int mret = mount("none",mount_ovfs_target,"overlay",0,mount_ovfs_options);
    if(mret) {
      XLOG(XLOG_ERROR,"mount_overlayfs: (%d) %s\n",errno,strerror(errno));
      return 1;
    }

    //if allowed by permissions try to make the target folder if not yet exists
    mkdir(mount_bind_target,0222);

    //prepare bind mount
    //if mount_bind_target is symlink, we must create an ABSOLUTE symlink to mount_source, and use this symlink as the mount_source for the mount
    struct stat mtarget_stat = {};
    lstat(mount_bind_target,&mtarget_stat);
    int target_is_symlink = S_ISLNK(mtarget_stat.st_mode);

    struct stat msource_stat = {};
    lstat(mount_bind_source,&msource_stat);
    int source_is_dir = S_ISDIR(msource_stat.st_mode);

    if(target_is_symlink && source_is_dir) {
      XLOG(XLOG_INFO,"target_is_symlink and source_is_dir\n");

      //hash source path and use the hash as link name
      char* mount_bind_source_symlink = NULL;
      char* hash = x_hash(mount_bind_source);
      asprintf(&mount_bind_source_symlink,"%s/%s.lnk",mount_files_dir,hash);
      XLOG(XLOG_INFO,"absolute symlink for mount_bind: %s --> %s\n",mount_bind_source_symlink,mount_bind_source);

      //create symlink if not already existing
      if(access(mount_bind_source_symlink, F_OK) != 0) {
        symlink(mount_bind_source,mount_bind_source_symlink);
      }
      mount_bind_source = mount_bind_source_symlink;
    }

    bm_s[currdir_idx] = mount_bind_source;
    bm_t[currdir_idx] = mount_bind_target;
    currdir_idx += 1;
  }

  //2 second cycle on newroot items to bind-mount overlayfs merges over the real root
  currdir_idx = 0;
  while(1) {
    if(currdir_idx>=diritems_num) break;
    struct dirent* diritem = diritems[currdir_idx];
    
    char* dirname = diritem->d_name;
    //skip hidden dirs and . and ..
    if(dirname[0]=='.') {
      currdir_idx += 1;
      continue;
    }
    
    XLOG(XLOG_INFO,"c2 dir: %s\n",dirname);

    //prepare bind mount paths
    char* mount_bind_target = bm_t[currdir_idx];
    char* mount_bind_source = bm_s[currdir_idx];

    //bind mount
    //new linux mount api, because so we can spacify AT_SYMLINK_NOFOLLOW and shadow via bind mount also symlinks in the host fs
    XLOG(XLOG_INFO,"bind mount target: %s source: %s\n",mount_bind_target,mount_bind_source);

    int fd_mount = syscall(SYS_open_tree, AT_FDCWD, mount_bind_source, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLONE);
    if(fd_mount==-1) {
      XLOG(XLOG_ERROR,"open_tree: %s\n",strerror(errno));
      return 1;
    }
    
    struct mount_attr attr = {};
    attr.propagation = MS_PRIVATE;
    int mret2 = syscall(SYS_mount_setattr, fd_mount, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT, &attr, sizeof(attr));
    if(mret2) {
      XLOG(XLOG_ERROR,"mount_setattr: %s\n",strerror(errno));
      return 1;
    }
    
    mret2 = syscall(SYS_move_mount, fd_mount, "", AT_FDCWD, mount_bind_target, MOVE_MOUNT_F_EMPTY_PATH);
    if(mret2) {
      XLOG(XLOG_ERROR,"move_mount: %s\n",strerror(errno));
      return 1;
    }
    
    mret2 = close(fd_mount);
    if(mret2) {
      XLOG(XLOG_ERROR,"close open_tree fd: %s\n",strerror(errno));
      return 1;
    }

    currdir_idx += 1;
  }

  return 0;
}

char* x_path_search(char *file) {
  //copied from
  //https://github.com/bminor/musl/blob/718f363bc2067b6487900eddc9180c84e7739f80/src/process/execvp.c#L9
  
  file = strdup(file);

  const char *p, *z, *path = getenv("PATH");
  size_t l, k;
  int seen_eacces = 0;

  errno = ENOENT;
  if (!*file) return NULL;

  if (strchr(file, '/'))
    return file;

  //if (!path) path = "/usr/local/bin:/bin:/usr/bin";
  k = strnlen(file, NAME_MAX+1);
  if (k > NAME_MAX) {
    errno = ENAMETOOLONG;
    return NULL;
  }
  l = strnlen(path, PATH_MAX-1)+1;

  for(p=path; ; p=z) {
    char b[l+k+1];
    z = strchrnul(p, ':');
    if (z-p >= l) {
      if (!*z++) break;
      continue;
    }
    memcpy(b, p, z-p);
    b[z-p] = '/';
    memcpy(b+(z-p)+(z>p), file, k+1);
    return strdup(b);
    switch (errno) {
    case EACCES:
      seen_eacces = 1;
    case ENOENT:
    case ENOTDIR:
      break;
    default:
      return NULL;
    }
    if (!*z++) break;
  }
  if (seen_eacces) errno = EACCES;
  return NULL;
}

int x_ld_execv(char *ld_bin, char *libpaths, int benv_libpaths, char *cmd, char **argv) {
  //https://man7.org/linux/man-pages/man8/ld.so.8.html

  ////search ld_bin fullpath if not already absolute
  //ld_bin = x_path_search(ld_bin);
  //search cmd fullpath if not already absolute
  cmd = x_path_search(cmd);

  //count args
  int argc = 0;
  while(argv[argc++]);

  //prepare ld args
  int maxldargs = 10;
  auto ld_args = x_realloc<char**>(nullptr,argc+maxldargs);
  int apos = 0;

  //ld path
  ld_args[apos++] = ld_bin;

  //disable ld cache we dont want .so files searched around in strange ways
  ld_args[apos++] = "--inhibit-cache";

  //ld argv0 required?
  //if(argc){
  //  ld_args[apos++] = "--argv0";
  //  ld_args[apos++] = cmd;
  //}

  //ld library path argument via cli if specified so
  if(libpaths && !benv_libpaths){
    ld_args[apos++] = "--library-path";
    ld_args[apos++] = libpaths;
  }

  //final cmd path
  ld_args[apos++] = cmd;

  //pass other arguments
  if(argc){
    int p = 1;
    while(argv[p++]){
      ld_args[apos++] = argv[p];
    }
  }

  //end null arg
  ld_args[apos++] = NULL;

  //if was specified use env var to pass lib paths instead of cli argument
  //doing this will enable lib paths for sub processes of the called executable
  if(libpaths && benv_libpaths){
    setenv("LD_LIBRARY_PATH",libpaths,1);
  }

  //print arguments
  if(XLOG_ISLVL(XLOG_INFO)) {
    int i = 0;
    char** parg = &ld_args[0];
    do {
      if(!*parg) break;
      XLOG(XLOG_INFO,"arg%d: %s\n",i, *parg);
      i += 1;
      parg += 1;
    } while(1);
  }

  //final exec
  int ret = execvp(ld_bin,ld_args);
  return ret;
}

//------------------------------------------------------------

int main(int argc, char **argv) {
  //setup log printing
  char* sxlog_velev = getenv("BIX_LOGLEVEL");
  if(sxlog_velev) {
    xlog_level = strtol(sxlog_velev, NULL, 10);
    //fprintf(stderr, "%d", xlog_level);
    XLOG(XLOG_INFO,"set loglevel to: %d\n", xlog_level);
  }
  
  //re-exec from memory on first run to avoid security problems:
  //https://github.com/advisories/GHSA-gxmr-w5mj-v8hh
  //https://www.scrivano.org/posts/2022-12-21-hide-self-exe/
  char* is_cloned = getenv("BIX_CLONED");
  XLOG(XLOG_INFO,"is_cloned: %s\n", is_cloned);
  if(!is_cloned) {
    putenv("BIX_CLONED=1");
    XLOG(XLOG_INFO,"re-exec from memory fd\n");
    x_memfd_execve("/proc/self/exe",argv,environ);
  }

  //determine entry name
  char* entry_name = basename(strdup(argv[0]));

  //determine BIX_BD (BASE DIR)
  auto bix_bd = realpath(dirname(strdup(argv[0])),NULL);
  setenv("BIX_BD",bix_bd,1);

  ////check if bix was called via a symlink
  //struct stat exec_stat = {};
  //lstat(argv[0],&exec_stat);
  //int is_symlink = S_ISLNK(exec_stat.st_mode);

  //determine BIX_CD (config dir)
  char* bix_cd = dirname(realpath(argv[0],NULL));

  //determine .bix cfg location
  char* bix_cfg = NULL;
  asprintf(&bix_cfg,"%s/%s.bix",bix_cd,entry_name);

  //XLOG(XLOG_INFO,"is_symlink: %d\n",is_symlink);
  XLOG(XLOG_INFO,"entry name: %s\n", entry_name);
  XLOG(XLOG_INFO,"BIX_BD: %s\n", bix_bd);
  XLOG(XLOG_INFO,"config path: %s\n", bix_cfg);

  //load {entry_name}.bix
  auto cfg = x_cfg_loadfile(bix_cfg);
  if(!cfg) {
    XLOG(XLOG_ERROR,"cannot load config file: %s\n",bix_cfg);
    return 1;
  }
  defer {
    free(cfg);
  };

  //config variables
  char* bix_mode = nullptr;
  char* bix_ld = nullptr;
  char* bix_ld_libpaths = nullptr;
  char* bix_ns_newroot = nullptr;
  char* bix_ns_tmpdir = nullptr;
  char* bix_cmd = nullptr;
  defer {
    free(bix_mode);
    free(bix_ld);
    free(bix_ld_libpaths);
    free(bix_ns_newroot);
    free(bix_ns_tmpdir);
    free(bix_cmd);
  };


  //cycle and set config vars
  auto pc = cfg;
  while(1) {
    auto m_key = *pc++;
    if(m_key==nullptr) break;
    auto m_val = *pc++;
    defer {
      free(m_key);
      free(m_val);
    };
    XLOG(XLOG_INFO,"k: %s\n", m_key);
    XLOG(XLOG_INFO,"v: %s\n", m_val);

    if(strcasecmp("mode",m_key)==0) {
      bix_mode = x_str_expenvvars(m_val);
    }
    if(strcasecmp("ld",m_key)==0) {
      bix_ld = x_str_expenvvars(m_val);
    }
    if(strcasecmp("ld_libpaths",m_key)==0) {
      bix_ld_libpaths = x_str_expenvvars(m_val);
    }
    if(strcasecmp("ns_newroot",m_key)==0) {
      bix_ns_newroot = x_str_expenvvars(m_val);
    }
    if(strcasecmp("ns_tmpdir",m_key)==0) {
      bix_ns_tmpdir = x_str_expenvvars(m_val);
    }
    if(strcasecmp("cmd",m_key)==0) {
      bix_cmd = x_str_expenvvars(m_val);
    }

    if(strcasecmp("pivot_root",m_key)==0) {
      char* new_root = m_val;
      new_root = x_str_expenvvars(new_root);
      //printf("pivot_root: %s\n",new_root);
      chdir(new_root);
      free(new_root);
      //int ret = pivot_root(".", ".");
      int pret = syscall(SYS_pivot_root, ".", ".");
      if(pret) perror("pivot_root");
      umount2(".", MNT_DETACH);
    }

    if(strcasecmp("chroot",m_key)==0) {
      char* new_root = m_val;
      new_root = x_str_expenvvars(new_root);
      //printf("chroot: %s\n",new_root);
      int pret = chroot(new_root);
      free(new_root);
      if(pret) perror("chroot");
    }

    //set env var
    if(strcasecmp("putenv",m_key)==0) {
      //printf("putenv\n");
      putenv(m_val);
    }

    //unset env var
    if(strcasecmp("unsetenv",m_key)==0) {
      //printf("unsetenv\n");
      unsetenv(m_val);
    }

    //make dirs (mainly for overlayfs workdirs)
    if(strcasecmp("mkpath",m_key)==0) {
      //printf("mkpath\n");
      char* mkpath = x_str_expenvvars(m_val);
      x_mkpath(mkpath,0222);
      free(mkpath);
    }
  }

  XLOG(XLOG_INFO,"cmd: %s\n", bix_cmd);
  XLOG(XLOG_INFO,"mode: %s\n", bix_mode);
  XLOG(XLOG_INFO,"ld: %s\n", bix_ld);
  XLOG(XLOG_INFO,"ld_libpaths: %s\n", bix_ld_libpaths);
  XLOG(XLOG_INFO,"ns_newroot: %s\n", bix_ns_newroot);
  XLOG(XLOG_INFO,"ns_tmpdir: %s\n", bix_ns_tmpdir);

  //change first argument to entry
  argv[0] = bix_cmd;

  if(XLOG_ISLVL(XLOG_INFO)) {
    int i = 0;
    char** parg = &argv[0];
    do {
      if(!*parg) break;
      XLOG(XLOG_INFO,"arg%d: %s\n",i, *parg);
      i += 1;
      parg += 1;
    } while(1);
  }

  //ld mode
  int ld_env = strcasecmp("ld_env",bix_mode)==0;
  if(ld_env || strcasecmp("ld",bix_mode)==0) {
    XLOG(XLOG_INFO,"ld_exec\n");
    int eret = x_ld_execv(bix_ld,bix_ld_libpaths,ld_env,bix_cmd,argv);
    XLOG(XLOG_ERROR,"ld_exec: %s %s\n",bix_cmd,strerror(errno));
    return 1;
  }
  //ns mode
  else {
    XLOG(XLOG_INFO,"ns_prepare\n");
    int nsperr = x_ns_prepare(bix_ns_newroot,bix_ns_tmpdir);
    if(nsperr) {
      XLOG(XLOG_ERROR,"ns_prepare: %s %s %s\n",bix_ns_newroot,bix_ns_tmpdir,strerror(errno));
      return 1;
    }

    XLOG(XLOG_INFO,"exec\n");
    int eret = execvpe(bix_cmd, argv, environ);
    //perror("execvpe");
    XLOG(XLOG_ERROR,"execvpe: %s %s\n",bix_cmd,strerror(errno));
    //char* errmsg = strerror(eret);
    //printf("execvpe: %s\n",errmsg);
  }
}