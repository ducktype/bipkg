#!/usr/bin/env bash

#EXTERNAL COMMANDS USED BY THIS BUILD SCRIPT: wget mkdir tar

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

#url="https://go.dev/dl/go1.20.4.linux-amd64.tar.gz"
url="https://go.dev/dl/go1.21rc2.linux-amd64.tar.gz"
url_file=${url##*/}
#url_dir=${url_file%.tar.xz}
#echo $url
#echo $url_file
#echo $url_dir
#exit


if [[ ! -e $script_dir/golang ]]
then
  if [[ ! -e $script_dir/$url_file ]]
  then
    echo "downloading golang..."
    wget -q $url -O $script_dir/$url_file
  fi
  echo "extracting golang..."
  mkdir -p $script_dir/golang
  tar --strip-components=1 -xf $script_dir/$url_file -C $script_dir/golang
  #mv $script_dir/$url_dir $script_dir/golang
fi
echo "building..."

GOARCH=amd64
GOOS=linux
CGO_ENABLED=0
GOPATH=
mkdir -p $script_dir/bin
cp $script_dir/../riprun/riprun $script_dir/src
$script_dir/golang/bin/go mod tidy -C $script_dir/src
$script_dir/golang/bin/go build -C $script_dir/src -o $script_dir/bin -trimpath -ldflags="-s -w"

echo "done"