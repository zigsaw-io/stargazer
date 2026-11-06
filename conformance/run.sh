#!/bin/sh
# Checks stargazer against containerd's Go package, estargz, both ways: Go's
# reader checks a blob stargazer made, and stargazer checks one Go made, of
# the same tar, which Go writes.
#
#   conformance/run.sh <stargazer> [<work dir>]
#
# Needs Go 1.25 or later, and the network the first time, for the module.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
sg=$1
work=${2:-$(mktemp -d)}
mkdir -p "$work"
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) exe=.exe ;; *) exe= ;; esac
(cd "$here/go" && go build -o "$work/conformance$exe" .)
check="$work/conformance$exe"
chunk=65536

"$check" mktar "$work/t.tar"

# stargazer's blob, read by Go and by stargazer.
"$sg" convert --chunk-size=$chunk "$work/t.tar" "$work/ours.esgz" >"$work/ours.txt"
toc=$(sed -n 's/^toc digest *//p' "$work/ours.txt")
"$check" check "$work/ours.esgz" "$toc" >"$work/ours.go-ls"
"$sg" verify --toc-digest="$toc" "$work/ours.esgz"

# Go's blob, read by stargazer and by Go.
go_toc=$("$check" build $chunk "$work/t.tar" "$work/go.esgz")
"$sg" verify --toc-digest="$go_toc" "$work/go.esgz"
"$check" check "$work/go.esgz" "$go_toc" >"$work/go.go-ls"

# Every reader sees the same tree in both. Go's reader lists a hard link as
# what it links to, so hard links are left out.
listing() { grep -v ' hard' | sort; }
"$sg" ls "$work/ours.esgz" | listing >"$work/ours.ls"
"$sg" ls "$work/go.esgz" | listing >"$work/go.ls"
listing <"$work/ours.go-ls" >"$work/ours.go-ls.sorted"
listing <"$work/go.go-ls" >"$work/go.go-ls.sorted"
diff "$work/ours.ls" "$work/go.ls"
diff "$work/ours.ls" "$work/ours.go-ls.sorted"
diff "$work/ours.ls" "$work/go.go-ls.sorted"

# And the same bytes, through stargazer.
for name in share/big.dat share/two.dat bin/tool; do
	"$sg" cat "$work/ours.esgz" "$name" >"$work/ours.cat"
	"$sg" cat "$work/go.esgz" "$name" >"$work/go.cat"
	cmp "$work/ours.cat" "$work/go.cat"
done

# Prioritized files, both ways, and the same order of entries in each: the
# blob's, unsorted, landmarks included.
printf 'share/two.dat\nbin/tool\n' >"$work/prio.txt"
"$sg" convert --chunk-size=$chunk --prioritized="$work/prio.txt" "$work/t.tar" "$work/ours-p.esgz" >"$work/ours-p.txt"
ptoc=$(sed -n 's/^toc digest *//p' "$work/ours-p.txt")
"$check" check "$work/ours-p.esgz" "$ptoc" >/dev/null
"$sg" verify --toc-digest="$ptoc" "$work/ours-p.esgz"
go_ptoc=$("$check" build $chunk "$work/t.tar" "$work/go-p.esgz" "$work/prio.txt")
"$sg" verify --toc-digest="$go_ptoc" "$work/go-p.esgz"
"$sg" ls "$work/ours-p.esgz" | awk '{ print $4 }' >"$work/ours-p.order"
"$sg" ls "$work/go-p.esgz" | awk '{ print $4 }' >"$work/go-p.order"
diff "$work/ours-p.order" "$work/go-p.order"
head -4 "$work/ours-p.order" | tr '\n' ' ' | grep -q '^share share/two.dat bin bin/tool $'

echo "conformance: ok ($(wc -l <"$work/ours.ls") entries, both ways, and prioritized)"
