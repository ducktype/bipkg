#!/usr/bin/env bash

#EXTERNAL COMMANDS USED BY THIS BUILD SCRIPT: wget mkdir tar

#SOME BASH SNIPPETS:
#path=/foo/bar/bim/baz/file.gif
#file=${path##*/}  
##$file is now 'file.gif'
##Remove the extension from a path-string:
#base=${file%.*}
##remove specific multiple extensions from file
#base2=${file%.tar.xz}
##${base} is now 'file'.
##keep dirname of a path
#dir=${path%/*}
##dir is now /foo/bar/bim/baz

#DOC LINKS:
#https://aykevl.nl/2018/04/codesize

#PURE BASH FUNCTION TO DETERMINE THE CURRENT BASH SCRIPT DIRECTORY ABSOLUTE PATH:
get_script_dir() {
  local wdir
  local scriptdir
  wdir="$PWD"; [ "$PWD" = "/" ] && wdir=""
  case "$0" in
    /*) scriptdir="${0}";;
    *) scriptdir="$wdir/${0#./}";;
  esac
  scriptdir="${scriptdir%/*}"
  REPLY=$scriptdir
}

get_script_dir
script_dir=$REPLY
#echo $script_dir

url="https://ziglang.org/builds/zig-linux-x86_64-0.11.0-dev.2639+4df87b40f.tar.xz"
url_file=${url##*/}
#url_dir=${url_file%.tar.xz}
#echo $url
#echo $url_file
#echo $url_dir
#exit


if [[ ! -e $script_dir/zig ]]
then
  if [[ ! -e $script_dir/$url_file ]]
  then
    echo "downloading zig..."
    wget -q $url -O $script_dir/$url_file
  fi
  echo "extracting zig..."
  mkdir -p $script_dir/zig
  tar --strip-components=1 -xf $script_dir/$url_file -C $script_dir/zig
  #mv $script_dir/$url_dir $script_dir/zig
fi
echo "building riprun..."
#./zig/zig cc -static -target x86_64-linux-musl treerun.c --name treerun
$script_dir/zig/zig cc -static -target x86_64-linux-musl $script_dir/riprun.c -o $script_dir/riprun -s
#$script_dir/zig/zig c++ -static -target x86_64-linux-musl $script_dir/treerun.c -o $script_dir/treerun -s
#$script_dir/zig/zig c++ -static -target x86_64-linux-musl $script_dir/treerun.c -o $script_dir/treerun -s -ffunction-sections -fdata-sections -flto -Wl,--gc-sections
#ldd $script_dir/treerun
