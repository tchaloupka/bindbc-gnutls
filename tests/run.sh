#!/bin/sh

set -e

BBC=0.3.2

if [ -z $DC ]; then DC="dmd"; fi
if [ $DC = "ldc2" ]; then DC="ldmd2"; fi

dub fetch bindbc-loader@$BBC --cache=local

# static
dub build --root ../ -c static
for f in [^_]*.d; do
    echo $f
    $DC -g -w -vcolumns -version=BindGnuTLS_Static ../libbindbc-gnutls.a \
        _loader.d $f -I../source/ -L-lgnutls -of=${f%.*} && ./${f%.*}
done

# staticBC
dub build --root ../ -c staticBC
for f in [^_]*.d; do
    $DC -betterC -g -w -vcolumns -version=BindGnuTLS_Static ../libbindbc-gnutls.a \
        _loader.d $f -I../source/ -L-lgnutls -of=${f%.*} && ./${f%.*}
done

# dynamic
dub build --root ../ -c dynamic
dub build --root .dub/packages/bindbc-loader-$BBC/bindbc-loader
for f in [^_]*.d; do
    $DC -g -w -vcolumns ../libbindbc-gnutls.a \
        .dub/packages/bindbc-loader-0.3.2/bindbc-loader/lib/libBindBC_Loader.a \
        -I.dub/packages/bindbc-loader-$BBC/bindbc-loader/source \
        _loader.d $f -I../source/ -of=${f%.*} && ./${f%.*}
done

# dynamicBC
dub build --root ../ -c dynamicBC
dub build --root .dub/packages/bindbc-loader-$BBC/bindbc-loader -c yesBC
for f in [^_]*.d; do
    $DC -betterC -g -w -vcolumns ../libbindbc-gnutls.a \
        .dub/packages/bindbc-loader-0.3.2/bindbc-loader/lib/libBindBC_Loader.a \
        -I.dub/packages/bindbc-loader-$BBC/bindbc-loader/source \
        _loader.d $f -I../source/ -of=${f%.*} && ./${f%.*}
done

# compilation test with various versions
for v in GNUTLS_3_5_1 GNUTLS_3_5_3 GNUTLS_3_5_4 GNUTLS_3_5_5 GNUTLS_3_5_6 GNUTLS_3_5_7 GNUTLS_3_5_9 GNUTLS_3_6_0 GNUTLS_3_6_2 \
    GNUTLS_3_6_3 GNUTLS_3_6_4 GNUTLS_3_6_5 GNUTLS_3_6_8 GNUTLS_3_6_9 GNUTLS_3_6_10 GNUTLS_3_6_12 GNUTLS_3_6_13 GNUTLS_3_6_14; do
    DFLAGS="-version=$v" dub build --root ../ -c dynamic --compiler=$DC
done
