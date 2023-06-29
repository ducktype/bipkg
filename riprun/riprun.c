/*
DOCS:
https://serverfault.com/questions/322906/how-do-i-do-a-bind-mount-over-a-symlink
https://github.com/Snorch/linux-helpers/blob/master/bindmount-v2.c
https://unix.stackexchange.com/questions/457299/losing-permissions-by-adding-capability
https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt
https://stackoverflow.com/questions/3064618/in-linux-how-can-i-completely-disregard-the-contents-of-etc-ld-so-cache

mount -t overlay overlay -o "lowerdir=/lower,upperdir=/upper,workdir=/work" "/merged"
findmnt -R -o SOURCE,FSROOT,TARGET,MAJ:MIN,FSTYPE,PROPAGATION,OPTIONS
cat /proc/self/mountinfo | grep ripkg

readelf -d ripcp_bundle/approot/usr/bin/php82
0x000000000000000f (RPATH)              Library rpath: [/lib:/usr/lib/x86_64-linux-gnu]

unshare -r -m /bin/bash
mkdir -p /opt/test_se/ofs/usr
mkdir -p /opt/test_se/ofs/usr.work
mount --no-mtab -t overlay -o lowerdir=/usr,upperdir=/opt/test_se/approot/usr,workdir=/opt/test_se/ofs/usr.work overlay --target /opt/test_se/ofs/usr
mount --no-mtab --bind /opt/test_se/ofs/usr /usr
cat /proc/sys/kernel/unprivileged_userns_clone
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <libgen.h>
#include <string.h>
#include <stdarg.h>
#include <sched.h>
#include <crypt.h>
#include <dirent.h>
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

int x_mkpath(char *dir, mode_t mode) {
  struct stat sb;
  if (!dir) {
    errno = EINVAL;
    return 1;
  }
  if (!stat(dir, &sb))
    return 0;
  //char* dc = strdupa(dir);
  x_mkpath(dirname(strdupa(dir)), mode);
  //free(dc);
  return mkdir(dir, mode);
}

char* x_readlink(char* symlink_path) {
  struct stat sl_stat = {};
  lstat(symlink_path,&sl_stat);
  int sl_size = sl_stat.st_size + 1;
  char* sl_value = malloc(sl_size);
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
  char* hash = malloc(128);
  crypt_r(data,"$1$",(struct crypt_data *)hash); //$1$ MD5
  int len = strlen(hash);
  hash = memmove(hash,hash+4,len-4+1); //skip $1$$ prefix in hash output
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

enum {
  XLOG_INFO = 10,
  XLOG_DEBUG = 20,
  XLOG_WARNING = 30,
  XLOG_ERROR = 40,
};
int xlog_level = XLOG_ERROR;
#define XLOG(level, fmt, ...) do { if (xlog_level >= level) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

//------------------------------------------------------------

int main(int argc, char **argv) {
  //setup log printing
  char* sxlog_velev = getenv("RIPRUN_LOGLEVEL");
  if(sxlog_velev) {
    xlog_level = atoi(sxlog_velev);
    XLOG(XLOG_INFO,"set loglevel to: %d\n", xlog_level);
  }

  //char** parg1 = &argv[0];
  //do {
  //  if(parg1[0]==NULL) break;
  //  XLOG(XLOG_INFO,"arg1: %s\n",parg1[0]);
  //  parg1 += 1;
  //} while(1);
  
  //re-exec from memory on first run to avoid security problems:
  //https://github.com/advisories/GHSA-gxmr-w5mj-v8hh
  //https://www.scrivano.org/posts/2022-12-21-hide-self-exe/
  char* is_cloned = getenv("_RIPRUN_CLONED");
  XLOG(XLOG_INFO,"is_cloned: %s\n", is_cloned);
  if(!is_cloned) {
    int binfd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    struct stat binfd_stat = {};
    fstat(binfd, &binfd_stat);
    int memfd = memfd_create("riprun:/proc/self/exe", MFD_CLOEXEC);
    sendfile(binfd, memfd, 0, binfd_stat.st_size);
    close(binfd);
    putenv("_RIPRUN_CLONED=1");
    XLOG(XLOG_INFO,"reexec\n");

    //char** parg2 = &argv[0];
    //do {
    //  if(!parg2[0]) break;
    //  XLOG(XLOG_INFO,"arg2: %s\n",parg2[0]);
    //  parg2 += 1;
    //} while(1);

    fexecve(memfd, argv, environ);
  }

  //get current process euid/egid
  uid_t euid = geteuid();
  gid_t egid = getegid();

  ////check root capability (not available in musl libc)
  //cap_t proc_caps = cap_get_proc();
  //cap_flag_value_t bcap_sys_admin = 0;
  //cap_get_flag(proc_caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &bcap_sys_admin);
  //int is_root = bcap_sys_admin != 0;
  //int is_root = euid == 0;
  //int is_root = 1; //default to think we are root

  //check if riprun was called via a symlink
  struct stat exec_stat = {};
  lstat(argv[0],&exec_stat);
  int is_symlink = S_ISLNK(exec_stat.st_mode);
  
  //determine riprun dir
  char* exec_path_dir = strdup(argv[0]);
  exec_path_dir = dirname(exec_path_dir);
  char *exec_path_abs = realpath(exec_path_dir,NULL);

  //determine entry name, using symlink name or default if riprun was runned directly
  char *entry_name = "_default";
  if(is_symlink) {
    entry_name = strdup(argv[0]);
    entry_name = basename(entry_name);
  }

  //determine config dir
  char* config_dir = NULL;
  asprintf(&config_dir,"%s/.riprun",exec_path_abs);
  //int conf_dir_fd = opendir(config_dir);

  //determine exec path from entry link
  char* entry_symlink_path = NULL;
  asprintf(&entry_symlink_path,"%s/entry/%s",config_dir,entry_name);
  char* entry_exec = x_readlink(entry_symlink_path);
  if(!entry_exec) {
    XLOG(XLOG_ERROR,"symlink returned buffer have been truncated, quitting\n");
    exit(1);
  }

  //determine approot path
  char* approot_symlink_path = NULL;
  asprintf(&approot_symlink_path,"%s/approot",config_dir);
  char *approot_path = realpath(approot_symlink_path,NULL);
  DIR* app_root_dir = opendir(approot_path);

  //determine and create the dir in which store overlayfs and bind mount required files and folders,
  //like work dirs merged dirs and eventually required symlinks
  char* mount_files_dir = NULL;
  asprintf(&mount_files_dir,"%s/.mount",config_dir);
  x_mkpath(mount_files_dir,0222);

  XLOG(XLOG_INFO,"is_symlink: %d\n",is_symlink);
  XLOG(XLOG_INFO,"riprun dir: %s\n", exec_path_abs);
  XLOG(XLOG_INFO,"riprun config dir: %s\n", config_dir);
  XLOG(XLOG_INFO,"entry symlink path: %s\n", entry_symlink_path);
  XLOG(XLOG_INFO,"entry name: %s\n", entry_name);
  XLOG(XLOG_INFO,"entry exec: %s\n", entry_exec);
  XLOG(XLOG_INFO,"approot symlink path: %s\n", approot_symlink_path);
  XLOG(XLOG_INFO,"approot: %s\n", approot_path);
  XLOG(XLOG_INFO,"mount_files_dir: %s\n", mount_files_dir);

  //unshare current process
  XLOG(XLOG_INFO,"unshare\n");
  int proc_has_cap_sys_admin = 1;
  int un_flags = CLONE_NEWNS;
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

  //map items in approot to the new filesystem namespace
  while(1) {
    struct dirent* diritem = readdir(app_root_dir);
    if(diritem==NULL) break;
    char* dirname = diritem->d_name;

    //skip hidden dirs and . and ..
    if(dirname[0]=='.') continue;
    
    XLOG(XLOG_INFO,"dir: %s\n",dirname);

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
    x_mkpath(mount_ovfs_merged,0222);
    x_mkpath(mount_ovfs_work,0222);
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
      //perror("mount_overlayfs");
      XLOG(XLOG_ERROR,"mount_overlayfs: %s\n",strerror(mret));
      exit(1);
    }

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
      asprintf(&mount_bind_source_symlink,"%s/%s",mount_files_dir,hash);
      XLOG(XLOG_INFO,"absolute symlink for mount_bind: %s --> %s\n",mount_bind_source_symlink,mount_bind_source);

      //create symlink if not already existing
      if(access(mount_bind_source_symlink, F_OK) != 0) {
        symlink(mount_bind_source,mount_bind_source_symlink);
      }
      mount_bind_source = mount_bind_source_symlink;
    }
    
    //bind mount
    //new linux mount api, because so we can spacify AT_SYMLINK_NOFOLLOW and shadow via bind mount also symlinks in the host fs
    XLOG(XLOG_INFO,"bind mount target: %s source: %s\n",mount_bind_target,mount_bind_source);

    int fd_mount = syscall(SYS_open_tree, AT_FDCWD, mount_bind_source, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLONE);
    if(fd_mount==-1) {
      //perror("open_tree");
      XLOG(XLOG_ERROR,"open_tree: %s\n",strerror(fd_mount));
      exit(1);
    }
    
    struct mount_attr attr = {};
    attr.propagation = MS_PRIVATE;
    int mret2 = syscall(SYS_mount_setattr, fd_mount, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT, &attr, sizeof(attr));
    if(mret2) {
      //perror("mount_setattr");
      XLOG(XLOG_ERROR,"mount_setattr: %s\n",strerror(mret2));
      exit(1);
    }
    
    mret2 = syscall(SYS_move_mount, fd_mount, "", AT_FDCWD, mount_bind_target, MOVE_MOUNT_F_EMPTY_PATH);
    if(mret2) {
      //perror("move_mount");
      XLOG(XLOG_ERROR,"move_mount: %s\n",strerror(mret2));
      exit(1);
    }
    
    mret2 = close(fd_mount);
    if(mret2) {
      //perror("close open_tree fd");
      XLOG(XLOG_ERROR,"close open_tree fd: %s\n",strerror(mret2));
      exit(1);
    }
  }
  closedir(app_root_dir);

  //exec final command, with same arguments (so skipping our first argument &argv[1])
  XLOG(XLOG_INFO,"exec\n");
  argv[0] = entry_exec; //change first argument to entry cmd?

  //print arguments
  char** parg = &argv[1];
  do {
    if(!parg[0]) break;
    XLOG(XLOG_INFO,"arg: %s\n",parg[0]);
    parg += 1;
  } while(1);
  
  int eret = execvpe(entry_exec, argv, environ);
  //perror("execvpe");
  XLOG(XLOG_ERROR,"execvpe: %s\n",strerror(eret));
  //char* errmsg = strerror(eret);
  //printf("execvpe: %s\n",errmsg);
}
