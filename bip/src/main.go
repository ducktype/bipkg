/*---------------------------------------------------------------------
INTERESTING LINKS/DOC:
https://github.com/namhyung/elftree/blob/master/main.go
In most cases look at first four bytes. If they are (in hex) 7F 45 46 4C, one necessary condition for ELF is satisfied.
https://0xcf9.org/2021/06/22/embed-and-execute-from-memory-with-golang/
https://stackoverflow.com/questions/27117896/how-to-pretty-print-variables
https://stackoverflow.com/questions/51779243/copy-a-folder-in-go
https://github.com/moby/moby/blob/master/daemon/graphdriver/copy/copy.go
apk info --who-owns /path/to/the/file
---------------------------------------------------------------------*/

package main

import "fmt"
import "flag"
import "os"
import "regexp"
import "path/filepath"
import "debug/elf"
import "bytes"
import "strings"
//import "errors"
//import tt "text/template"
//import ht "html/template"

/*---------------------------------------------------------------------*/

//official experimental golang libs, slices package will be included in golang 1.21
//import "golang.org/x/exp/slices"
import "slices"
//import "golang.org/x/sys/unix"

/*---------------------------------------------------------------------*/

//some useful third-party modules:
//import "github.com/davecgh/go-spew/spew"
import cp "github.com/otiai10/copy"
//import _ "github.com/edwingeng/deque/v2"
//import _ "github.com/wk8/go-ordered-map"
//import _ "github.com/sourcegraph/conc"
//import _ "github.com/go-co-op/gocron"

/*---------------------------------------------------------------------*/
import _ "embed" //related to special go:embed comments
//embed exe executable
//go:embed bix
var exebinstub []byte
/*---------------------------------------------------------------------*/

type LdLocator struct {
	Root        string
	SearchPaths map[string]bool
	SoMap 			map[string][]string
}

func NewLdLocator() *LdLocator {
	return &LdLocator{
    SearchPaths: make(map[string]bool),
    SoMap: make(map[string][]string),
  }
}

func (ldl *LdLocator) IndexPaths(ld_search []string) {
	//var so_map_paths = make(map[string][]string)
	var rx = regexp.MustCompile(`(?ims)\.so([\.\d]+)?$`)
	var i = 0
	for {
		if i>=len(ld_search) { break }
		var lp = ld_search[i]
		exists := ldl.SearchPaths[lp];
		//fmt.Printf("check: %q exists: %v\n", lp, exists)
		if exists { 
			i += 1
			continue
		}
		ldl.SearchPaths[lp] = true
		filepath.WalkDir(lp, func(path string, info os.DirEntry, err error) error {
			//var slp string
			//path does not exists or error
			if info == nil || err != nil {
				return nil
			}
			if info.Type() & os.ModeSymlink == os.ModeSymlink {
				//fmt.Printf("is_symlink: %q\n", path)
				//slp, _ = filepath.EvalSymlinks(path)
				var slp, _ = os.Readlink(path)
				if filepath.IsAbs(slp) {
					slp = filepath.Join(ldl.Root,slp)
				} else {
					slp = filepath.Join(filepath.Dir(path),slp)
				}
				slp = filepath.Clean(slp)
				ld_search = slices.Insert(ld_search,i+1,slp)
			}
			//skip dirs
			if info.IsDir() {
				return nil
			}
			var bn = filepath.Base(path)
			//check extension
			//if filepath.Ext(path) != ".so" {
			if !rx.MatchString(path) {
				return nil
			}
			if slices.Index(ldl.SoMap[bn],path) == -1 {
				//if path == "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" {
				//	fmt.Printf("ld_search: %q\n", ld_search)
				//	panic("B")
				//}
				ldl.SoMap[bn] = append(ldl.SoMap[bn],path)
			}
			return nil
		})
		i += 1
	}
	//fmt.Printf("ld_search: %q\nso_map_paths: %q\n", ld_search, so_map_paths)
	//os.Exit(3)
	//return so_map_paths
}

func get_elf_deps(elfpath string,interponly bool) ([]string, string, string) {
	var so_names []string
	var sinterp string
	var rpath string
	//fmt.Printf("get_elf_deps: %q\n", elfpath)
	elf_file, err := elf.Open(elfpath)
  if err != nil { return so_names, sinterp, rpath }
  defer elf_file.Close()

  interp_sec := elf_file.Section(".interp")
  if interp_sec != nil {
	  interp, err := interp_sec.Data()
	  if err == nil {
		  interp = interp[:len(interp)-1]
		  sinterp = string(interp)
		  //fmt.Printf("interp: %q\n", sinterp)
		}
	}

	if interponly { return so_names, sinterp, rpath }
  
  dynamic_sec := elf_file.Section(".dynamic")
  if dynamic_sec == nil { return so_names, sinterp, rpath }
  dynamic_data, err := dynamic_sec.Data()
  if err != nil { return so_names, sinterp, rpath }

  dynstr_sec := elf_file.Section(".dynstr")
  if dynstr_sec == nil { return so_names, sinterp, rpath }
  dynstr_data, err := dynstr_sec.Data()
  if err != nil { return so_names, sinterp, rpath }

  var i uint64
  var count = uint64(dynamic_sec.Size / dynamic_sec.Entsize)
	for i = 0; i < count; i++ {
		var tag, val uint64
		if elf_file.Class == elf.ELFCLASS64 {
			tag = elf_file.ByteOrder.Uint64(dynamic_data[(i*2+0)*8 : (i*2+1)*8])
			val = elf_file.ByteOrder.Uint64(dynamic_data[(i*2+1)*8 : (i*2+2)*8])
		} else {
			tag = uint64(elf_file.ByteOrder.Uint32(dynamic_data[(i*2+0)*4 : (i*2+1)*4]))
			val = uint64(elf_file.ByteOrder.Uint32(dynamic_data[(i*2+1)*4 : (i*2+2)*4]))
		}
		dtag := elf.DynTag(tag)
		switch dtag {
			//case elf.DT_NULL:
			//	break
			//case elf.DT_SONAME:
			//	fallthrough
			case elf.DT_RPATH:
				//TODO: support $ORIGIN placeholder in rpath
				idx := uint64(bytes.Index(dynstr_data[val:],[]byte("\x00")))
				sval := string(dynstr_data[val : val+idx])
				rpath = sval
				break
			//case elf.DT_RUNPATH:
			//	fallthrough
			case elf.DT_NEEDED:
				idx := uint64(bytes.Index(dynstr_data[val:],[]byte("\x00")))
				sval := string(dynstr_data[val : val+idx])
				//if len(sval) > 0 {
				if filepath.Base(sinterp) != sval {
					so_names = append(so_names, sval)
				}
				break
			//default:
			//	ret = append(ret, val)
			//	break
		}
	}
  //fmt.Printf("so_names: %q\n", so_names)
  //os.Exit(1)
  return so_names, sinterp, rpath
}

func conf_parse(cfg_data string, default_key string) map[string][]string {
	var cfg = make(map[string][]string)
	//parse configuration data
	var rx = regexp.MustCompile(`(?ims)^\s*(?P<rem>#)?\s*(?P<k>[^=$]*?)(?:\s*=\s*(?P<v>[^$]*?)\s*)?$`)
	var matches = rx.FindAllStringSubmatch(cfg_data,-1)
	for _, match := range matches {
		var comment = match[1]
		var k = match[2]
		var v = match[3]
		if len(comment) > 0 { continue }
		if len(v) == 0 && len(k) == 0 { continue }
		if len(v) == 0 && len(k) > 0 {
			v = k
			k = default_key
		}
		//fmt.Printf("k: %q v: %q\n", k,v)
		cfg[k] = append(cfg[k],v)
	}
	return cfg
}

/*---------------------------------------------------------------------*/

func main() {
	//fmt.Printf("riprun embed len: %v\n", len(riprun))

	//configure arguments
	var cfg_path = flag.String("c", "exepkg.ini", "exepkg.ini path")
	var src_root = flag.String("s", ".", "source root path to which exepkg.ini paths are considered relative to")
	var dst_root = flag.String("d", "", "destination directory to wich files are copied to")
	flag.Parse()

	var cfg_name = strings.TrimSuffix(filepath.Base(*cfg_path), filepath.Ext(*cfg_path))
	if(len(*dst_root)==0) {
		var ss = "./"+cfg_name
		dst_root = &ss
		//fmt.Printf("cfg_name: %q\ndst_root: %q\n", cfg_name, *dst_root)
	}


	//print arguments
	fmt.Printf("cfg_path: %q\n", *cfg_path)
	
	
	//read configuration file
	b, err := os.ReadFile(*cfg_path)
  if err != nil {
      fmt.Print(err)
  }
  var cfg_data = string(b)
	//fmt.Println(cfg_data)

	//configuration variables
	var cfg = conf_parse(cfg_data,"path")
	//fmt.Printf("cfg: %q\n", cfg)
	//spew.Dump(cfg)

	if len(cfg["src_root"])>0 && len(cfg["src_root"][0])>0 {
		src_root = &cfg["src_root"][0];
	}

	sr, _ := filepath.EvalSymlinks(*src_root)
	src_root = &sr
	//dr, _ := filepath.EvalSymlinks(*dst_root)
	//dst_root = &dr

	fmt.Printf("src_root: %q\n", *src_root)
	fmt.Printf("dst_root: %q\n", *dst_root)

	if len(*src_root)==0 || len(*dst_root)==0 || *src_root==*dst_root || *dst_root=="/" {
		panic("Conf Error!")
	}

	//remap source paths
	for ip, _ := range cfg["path"] {
		cfg["path"][ip] = filepath.Join(*src_root, cfg["path"][ip])
	}
	for ip, _ := range cfg["ld_search"] {
		cfg["ld_search"][ip] = filepath.Join(*src_root, cfg["ld_search"][ip])
	}

	//spew.Dump(cfg)
	

	//cycle source paths
	//var ld_map map[string][]string
	var ldl = NewLdLocator()
	ldl.Root = *src_root
	var paths_map = make(map[string]bool) //to avoid duplicate paths
	var paths = slices.Clone(cfg["path"]) //MMMMM?
	var exe_entries []string
	var i = 0
	for {
		if i>=len(paths) { break }
		var rp = paths[i]
		paths_map[rp] = true

		//fmt.Printf("%q\n", rp)

		filepath.WalkDir(rp, func(path string, info os.DirEntry, err error) error {
			//path does not exists or error
			if info == nil || err != nil {
				return nil
			}

			var append_paths []string

			if info.Type() & os.ModeSymlink == os.ModeSymlink {
				//var slp, _ = filepath.EvalSymlinks(path)
				var slp, _ = os.Readlink(path)
				if filepath.IsAbs(slp) {
					slp = filepath.Join(*src_root,slp)
				} else {
					slp = filepath.Join(filepath.Dir(path),slp)
				}
				slp = filepath.Clean(slp)
				/*if slpi == nil {
					fmt.Printf("not found: %q path: %q\n", slp, path)
					os.Exit(1)
					return nil
				}*/

				if len(slp) > 0 {
					slpi, _ := os.Stat(path)
					if slpi!=nil && !slpi.IsDir() {
						var _, interp, _ = get_elf_deps(slp,true)
						//fmt.Printf("check symlink interp: %q %q\n",path,interp)
						if len(interp) > 0 && slices.Index(cfg["path"],path) != -1 {
							exe_entries = append(exe_entries, path)
						}
					}
					//fmt.Printf("symlink: %q -> %q\n", path, slp)
					append_paths = append(append_paths,slp)
				}
			} else if info.Type().IsRegular() {
				append_paths = append(append_paths,path)

				var so_names, interp, rpath = get_elf_deps(path,false)
				if len(interp) > 0 && slices.Index(cfg["path"],path) != -1 {
					//fmt.Printf("has interp: %q interp: %q rpath: %q",path,interp, rpath)
					exe_entries = append(exe_entries, path)
				}
				if len(interp) > 0 {
					//spew.Dump(interp)
					//var slp, _ = filepath.Rel(path, interp)
					var slp = filepath.Join(*src_root, interp)
					//var slp, _ = filepath.EvalSymlinks(interp)
					//var slp = interp
					//if filepath.IsAbs(slp) {
					//	slp = filepath.Join(*src_root,slp)
					//} else {
					//	slp = filepath.Join(filepath.Dir(path),slp)
					//}
					//slp = filepath.Clean(slp)
					//xp,_ := filepath.Rel(*src_root,path)
					//fmt.Printf("interp for: %q %q\n",xp,slp)
					append_paths = append(append_paths,slp)
				}
				if len(so_names) > 0 {
					//spew.Dump(so_names)
					xp,_ := filepath.Rel(*src_root,path)
					fmt.Printf("deps for: %q %q\n",xp,so_names)
					//if ld_map == nil {
					if len(ldl.SearchPaths) == 0 {
						//ld_map = get_ld_map(cfg["ld_search"])
						ldl.IndexPaths(cfg["ld_search"])
						//spew.Dump(cfg["ld_search"])
						//spew.Dump(ldl.SoMap["ld-linux-x86-64.so.2"])
						//panic("A")
					}
					if len(rpath)>0 {
						xrp := filepath.Join(*src_root,rpath)
						ldl.IndexPaths([]string{xrp})
					}
					for _,sn := range so_names {
						//sn = filepath.Join(*src_root, sn)
						//if !filepath.IsAbs(sn) {
						if len(ldl.SoMap[sn]) == 0 {
							fmt.Printf("error: unable to find dependency: %q for: %q\n", sn, xp)
							continue
						}
						if len(ldl.SoMap[sn]) > 1 {
							//TODO: report duplicate warnings only at the end
							fmt.Printf("warning dependency resolving to multiple paths: %q for executable: %q copying all paths: %q\n", sn, xp, ldl.SoMap[sn])
						}
						//sn = ld_map[sn][0]
						//if sn == "ld-linux-x86-64.so.2" {
						//	spew.Dump(ldl.SoMap[sn])
						//	panic("A")
						//}
						append_paths = append(append_paths,ldl.SoMap[sn]...)
					}
				}
			}
			for _, ap := range append_paths {
				if paths_map[ap] { continue }
				paths_map[ap] = true
				//fmt.Printf("add: %q\n", ap)
				paths = slices.Insert(paths,i+1,ap)
			}
			return nil
		})
		i += 1
	}

	//fmt.Printf("cfg: %q\n", cfg)
	//fmt.Printf("ld_map: %q\n", ld_map)
	//fmt.Printf("paths: %q\n", paths)
	//pp.Print(paths)
	//dump.P(paths)
	//spew.Dump(cfg)
	//spew.Dump(paths)
	//spew.Dump(exe_entries)

	//TODO: by default overwrite only elf/so files and symlink to binary files
	//TODO: cp.Copy has no option to copy always first copy files then symlinks or file not found could happen
	//copy paths to dest
	for _, s := range paths {
		sr, _ := filepath.Rel(*src_root,s)
		d := filepath.Join(*dst_root,"approot",sr)
		var xs, _ = filepath.Rel(*src_root,s)
		var xd, _ = filepath.Rel(*dst_root,d)
		fmt.Printf("copy from: %q to: %q\n", xs, xd)
		//dp = filepath.Dir(d)
		//os.MkdirAll(dp, 0222)

		//if false {
			err := cp.Copy(s,d)
			if err != nil {
				fmt.Println(err)
			}
		//}
	}

	//put riprun executable, config, and links inside the destination dir
	rrpd := filepath.Join(*dst_root,".riprun")
	os.MkdirAll(rrpd, 0222)

	rrp := filepath.Join(*dst_root,".riprun/riprun")
	os.WriteFile(rrp, exebinstub, 0777)

	rrpde := filepath.Join(*dst_root,".riprun/entry")
	os.MkdirAll(rrpde, 0222)

	var ar_slp = filepath.Join(*dst_root,".riprun/approot")
	os.Remove(ar_slp)
	os.Symlink("../approot", ar_slp)


	//make unique exe_entries because could have duplicates
	slices.Sort(exe_entries)
	exe_entries = slices.Compact(exe_entries)
	
	for _, s := range exe_entries {
		sr, _ := filepath.Rel(*src_root,s)
		d := filepath.Join(*dst_root,"approot",sr)
		fmt.Printf("executable: %q\n", d)
		bn := filepath.Base(d)
		var entry_path = "/" + sr

		var e_slp = filepath.Join(*dst_root,".riprun/entry",bn)
		os.Remove(e_slp)
		os.Symlink(entry_path, e_slp)

		var slp = filepath.Join(*dst_root,bn)
		os.Remove(slp)
		os.Symlink(".riprun/riprun", slp)
	}

  fmt.Println("end")
}
