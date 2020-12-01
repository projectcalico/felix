#!/bin/bash

for path in $(grep -r --no-filename '#include' *.[ch] | grep -oP '\<\K.+(?=\>)'  | sort -u); do
  echo "==== $path ===="
  for kern_file in $(find ../kern-src | grep $path | grep -v common/arch); do
    p="$(echo "$kern_file" |  cut -d / -f4- )"
    echo "$kern_file -> $p"
    mkdir -p "$(dirname $p)"
    cp "$kern_file" "$p"
  done
done
