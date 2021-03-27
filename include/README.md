# Contribution

Current headers version is from `v3.6.15`.

Bindings are generated using [dstep](https://code.dlang.org/packages/dstep) like this:

```BASH
dstep --comments=false --single-line-function-signatures=true -o ../../source/bindbc/gnutls/ -I.. *
```

Then they were manually modified to compile and reordered for module functions being at the bottom. Then functions were manually taken and modified for dynamic binding.

After that, compile time checks were added based on API changes in versions back to `3.5.0` to support older versions too.

To update the bindings, it would probably be more efficient to just compare changes in the source header files and apply the differences manually.
