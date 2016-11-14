gcc -E -x c -w $@ | grep -e "^#" -v
