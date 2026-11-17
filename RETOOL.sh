#!/usr/bin/env bash
# retool.sh - simple static reverse-engineering triage tool (bash).
# Needs: bash 4+, coreutils, binutils (strings), awk, xxd (or hexdump).
#
#   retool.sh info    <file>
#   retool.sh strings <file> [-n MINLEN] [-i]
#   retool.sh hex     <file> [-o OFFSET] [-l LENGTH]
#   retool.sh all     <file>

set -u
LC_ALL=C

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ---------- low-level readers ----------
rdhex() { od -An -v -tx1 -j "$1" -N "$2" -- "$FILE" | tr -d ' \n'; }

# read unsigned int: offset, length -> decimal (honours $ENDIAN: le|be)
uint() {
  local h r="" i
  h=$(rdhex "$1" "$2")
  [[ -z $h ]] && { echo 0; return; }
  if [[ ${ENDIAN:-le} == le ]]; then
    for ((i=${#h}-2; i>=0; i-=2)); do r+=${h:i:2}; done
  else r=$h; fi
  echo $((16#$r))
}

entropy() {
  od -An -v -tu1 -w16 | awk '
    { for (i=1;i<=NF;i++) { c[$i]++; n++ } }
    END { if (!n) { print "0.00"; exit }
          for (k in c) { p=c[k]/n; h-=p*log(p)/log(2) }
          printf "%.2f\n", h }'
}

# ---------- file identification ----------
detect() {
  local m4 m2
  m4=$(rdhex 0 4); m2=${m4:0:4}
  case $m4 in
    7f454c46) echo "ELF executable"; return;;
    cffaedfe) echo "Mach-O 64-bit"; return;;
    cafebabe) echo "Mach-O fat / Java class"; return;;
    504b0304) echo "ZIP / APK / JAR / DOCX"; return;;
    25504446) echo "PDF document"; return;;
    89504e47) echo "PNG image"; return;;
    6465780a) echo "Android DEX"; return;;
  esac
  case $m2 in
    4d5a) echo "PE / DOS executable"; return;;
    2321) echo "Script (shebang)"; return;;
  esac
  echo "Unknown / raw data"
}

entropy_verdict() {
  awk -v e="$1" 'BEGIN{ if (e>7.2) print "likely packed/encrypted";
                         else if (e>4) print "normal"; else print "low (sparse/text)" }'
}

# ---------- format parsers ----------
parse_elf() {
  local cls type mach entry
  [[ $(rdhex 4 1) == 02 ]] && cls=64 || cls=32
  [[ $(rdhex 5 1) == 01 ]] && ENDIAN=le || ENDIAN=be
  case $(uint 16 2) in 1) type=REL;; 2) type=EXEC;; 3) type="DYN (PIE/so)";; 4) type=CORE;; *) type=other;; esac
  case $(uint 18 2) in 3) mach=x86;; 62) mach=x86-64;; 40) mach=ARM;; 183) mach=AArch64;; 8) mach=MIPS;; *) mach=unknown;; esac
  if [[ $cls == 64 ]]; then entry=$(uint 24 8); else entry=$(uint 24 4); fi
  printf '%-9s: %s-bit\n%-9s: %s\n%-9s: %s\n%-9s: 0x%x\n' \
    class "$cls" type "$type" machine "$mach" entry "$entry"
}

parse_pe() {
  ENDIAN=le
  local pe mach nsec ts optsz chars opt magic fmt dll=no ep so i off name vaddr rsize rptr e warn
  pe=$(uint 60 4)
  [[ $(rdhex "$pe" 4) == 50450000 ]] || return 0
  case $(uint $((pe+4)) 2) in 332) mach=x86;; 34404) mach=x64;; 448) mach=ARM;; 43620) mach=ARM64;; *) mach=unknown;; esac
  nsec=$(uint $((pe+6)) 2); ts=$(uint $((pe+8)) 4)
  optsz=$(uint $((pe+20)) 2); chars=$(uint $((pe+22)) 2)
  (( chars & 0x2000 )) && dll=yes
  opt=$((pe+24)); magic=$(uint "$opt" 2)
  (( magic == 0x20b )) && fmt=PE32+ || fmt=PE32
  ep=$(uint $((opt+16)) 4)
  printf '%-9s: %s\n%-9s: %s\n%-9s: %s\n%-9s: 0x%x\n%-9s: %s\n' \
    format "$fmt" machine "$mach" timestamp "$ts" entry_rva "$ep" dll "$dll"
  echo "Sections :"
  printf '  %-10s%-12s%-10s%s\n' name vaddr rawsize entropy
  so=$((opt+optsz))
  for ((i=0; i<nsec; i++)); do
    off=$((so+i*40))
    name=$(dd if="$FILE" bs=1 skip="$off" count=8 2>/dev/null | tr -d '\0')
    vaddr=$(uint $((off+12)) 4); rsize=$(uint $((off+16)) 4); rptr=$(uint $((off+20)) 4)
    e=$(tail -c +$((rptr+1)) -- "$FILE" | head -c "$rsize" | entropy)
    warn=""; awk -v e="$e" 'BEGIN{exit !(e>7.2)}' && warn="  <-- high"
    printf '  %-10s0x%-10x%-10s%s%s\n' "$name" "$vaddr" "$rsize" "$e" "$warn"
  done
}

# ---------- commands ----------
cmd_info() {
  local size ent algo m4
  size=$(stat -c%s -- "$FILE")
  ent=$(entropy < "$FILE")
  printf '%-9s: %s\n%-9s: %s bytes\n%-9s: %s\n' File "$FILE" Size "$size" Type "$(detect)"
  for algo in md5 sha1 sha256; do
    printf '%-9s: %s\n' "${algo^^}" "$("${algo}sum" -- "$FILE" | cut -d' ' -f1)"
  done
  printf '%-9s: %s / 8.00  (%s)\n' Entropy "$ent" "$(entropy_verdict "$ent")"
  m4=$(rdhex 0 4)
  [[ ${m4:0:4} == 4d5a ]] && parse_pe
  [[ $m4 == 7f454c46 ]] && parse_elf
  return 0
}

cmd_strings() {
  local n=4 only=0
  while (( $# )); do case $1 in
    -n) n=$2; shift 2;;
    -i|--interesting) only=1; shift;;
    *) die "unknown option: $1";; esac
  done
  { strings -a -t x -n "$n" -- "$FILE"        | sed -E 's/^ *([0-9a-f]+) (.*)$/\1\t\2/' | tag A "$only"
    strings -a -t x -e l -n "$n" -- "$FILE"   | sed -E 's/^ *([0-9a-f]+) (.*)$/\1\t\2/' | tag W "$only"
  } | sort -s -k1,1
}

# tag <enc> <only_interesting>  (reads "offset<TAB>string")
tag() {
  awk -F'\t' -v enc="$1" -v only="$2" '
    { t=""; s=$2; ls=tolower(s)
      if (s ~ /https?:\/\/[^ "<>]+/)                                  t=t "url,"
      if (s ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)                       t=t "ipv4,"
      if (s ~ /[A-Za-z0-9._+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+/)       t=t "email,"
      if (s ~ /([A-Za-z]:\\|\/etc\/|\/tmp\/|\/bin\/)[^ "]+/)          t=t "path,"
      if (ls ~ /hkey_[a-z_]+\\|software\\/)                           t=t "registry,"
      if (s ~ /(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary|GetProcAddress|WinExec|ShellExecute|execve|ptrace|strcpy|sprintf)/) t=t "api,"
      if (ls ~ /(password|passwd|secret|api[_-]?key|token) *[=:] *[^ ]+/) t=t "secret,"
      sub(/,$/, "", t)
      if (only && t == "") next
      off=$1; while (length(off) < 8) off="0" off
      printf "%s %s %s%s\n", off, enc, s, (t != "" ? "  [" t "]" : "")
    }'
}

cmd_hex() {
  local off=0 len=256
  while (( $# )); do case $1 in
    -o) off=$(( $2 )); shift 2;;
    -l) len=$2; shift 2;;
    *) die "unknown option: $1";; esac
  done
  if command -v xxd >/dev/null; then
    xxd -s "$off" -l "$len" -- "$FILE"
  else
    hexdump -C -s "$off" -n "$len" -- "$FILE"
  fi
}

# ---------- main ----------
[[ $# -ge 1 ]] || usage 1
CMD=$1; shift
[[ $CMD == -h || $CMD == --help || $CMD == help ]] && usage 0
[[ $# -ge 1 ]] || usage 1
FILE=$1; shift
[[ -f $FILE ]] || die "$FILE not found"

case $CMD in
  info)    cmd_info;;
  strings) cmd_strings "$@";;
  hex)     cmd_hex "$@";;
  all)     cmd_info; echo; echo "--- interesting strings ---"; cmd_strings -n 5 -i;;
  *)       usage 1;;
esac
