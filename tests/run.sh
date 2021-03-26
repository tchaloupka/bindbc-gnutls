#!/bin/sh

set -e -o pipefail

if [ -z $DC ]; then DC="dmd"; fi
if [ $DC = "ldc2" ]; then DC="ldmd2"; fi

# static
dub build --root ../ -c static
for f in *.d; do
    $DC -g -w -vcolumns ../libbindbc-gnutls.a $f -I../source/ -L-lgnutls && ./${f%.*}
done

# staticBC
dub build --root ../ -c staticBC
for f in *.d; do
    $DC -betterC -g -w -vcolumns ../libbindbc-gnutls.a $f -I../source/ -L-lgnutls && ./${f%.*}
done
