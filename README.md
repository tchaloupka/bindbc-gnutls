# bindbc-gnutls

[![Actions Status](https://github.com/tchaloupka/bindbc-gnutls/workflows/ci/badge.svg)](https://github.com/tchaloupka/bindbc-gnutls/actions)
[![Latest version](https://img.shields.io/dub/v/bindbc-gnutls.svg)](https://code.dlang.org/packages/bindbc-gnutls)
[![Dub downloads](https://img.shields.io/dub/dt/bindbc-gnutls.svg)](http://code.dlang.org/packages/bindbc-gnutls)
[![license](https://img.shields.io/github/license/tchaloupka/bindbc-gnutls.svg)](https://github.com/tchaloupka/bindbc-gnutls/blob/master/LICENSE)

**Note: This is an unofficial bindbc package, please don't contact Mike for help.**

This project provides both static and dynamic bindings to the [GnuTLS](https://gnutls.org/) library. They are `@nogc` and `nothrow` compatible and can be compiled for compatibility with `-betterC`.

GnuTLS `v3.6.15` was used to generate these bindings so it should be ABI `v3.4.0` compatible.

## License

This library source is licensed with [BSL-1.0](https://opensource.org/licenses/BSL-1.0).

But for static binding, please note that GnuTLS itself is licensed in [LGPLv2.1+](https://opensource.org/licenses/LGPL-2.1) so these bindings must be used in a corresponding way.

## Usage

By default, `bindbc-gnutls` is configured to compile as a dynamic binding that is not `-betterC` compatible. The dynamic binding has no link-time dependency on the GnuTLS library, so the GnuTLS shared library must be manually loaded at runtime. When configured as a static binding, there is a link-time dependency on the GnuTLS library (and it's Dane extension if needed); either the static library or the appropriate file for linking with shared libraries on your platform (see below).

When using DUB to manage your project, the static binding can be enabled via a DUB `subConfiguration` statement in your project's package file. `-betterC` compatibility is also enabled via subconfigurations.

To use GnuTLS, add `bindbc-gnutls` as a dependency to your project's package config file. For example, the following is configured to GnuTLS as a dynamic binding that is not `-betterC` compatible:

### dub.json

```JSON
dependencies {
    "bindbc-gnutls": "~>1.0.0",
}
```

### dub.sdl

```SDL
dependency "bindbc-gnutls" version="~>1.0.0"
```

### Minimal GnuTLS library version selection

By default, binding is compiled with symbols defined in GnuTLS `v3.5.0`.
If symbols from higher versions are required, binding user must specify this with `version` directive (through compiler switch or dub file).

You can check what version the binding was compiled for using `gnuTLSSupport` constant.

Supported versions:

| GnuTLS version |    version    |
| -------------- | ------------- |
|     v3.5.0     | GNUTLS_3_5_0  |
|     v3.5.1     | GNUTLS_3_5_1  |
|     v3.5.2     | GNUTLS_3_5_1  |
|     v3.5.3     | GNUTLS_3_5_3  |
|     v3.5.4     | GNUTLS_3_5_4  |
|     v3.5.5     | GNUTLS_3_5_5  |
|     v3.5.6     | GNUTLS_3_5_6  |
|     v3.5.7     | GNUTLS_3_5_7  |
|     v3.5.8     | GNUTLS_3_5_7  |
|     v3.5.9     | GNUTLS_3_5_9  |
|     v3.5.10    | GNUTLS_3_5_9  |
|     v3.5.11    | GNUTLS_3_5_9  |
|     v3.5.12    | GNUTLS_3_5_9  |
|     v3.5.13    | GNUTLS_3_5_9  |
|     v3.5.14    | GNUTLS_3_5_9  |
|     v3.5.15    | GNUTLS_3_5_9  |
|     v3.5.16    | GNUTLS_3_5_9  |
|     v3.5.17    | GNUTLS_3_5_9  |
|     v3.5.18    | GNUTLS_3_5_9  |
|     v3.6.0     | GNUTLS_3_6_0  |
|     v3.6.2     | GNUTLS_3_6_2  |
|     v3.6.3     | GNUTLS_3_6_3  |
|     v3.6.4     | GNUTLS_3_6_4  |
|     v3.6.5     | GNUTLS_3_6_5  |
|     v3.6.8     | GNUTLS_3_6_8  |
|     v3.6.9     | GNUTLS_3_6_9  |
|     v3.6.10    | GNUTLS_3_6_10 |
|     v3.6.12    | GNUTLS_3_6_12 |
|     v3.6.13    | GNUTLS_3_6_13 |
|     v3.6.14    | GNUTLS_3_6_14 |

Note that some GnuTLS versions doesn't come with their own compiler version constant. It's because that library version haven't introduced API change and is compatible with previous version binding.

Use minimal required version to compile the library so newer ones can still be loaded although without the new API additions.

### The dynamic binding

The dynamic binding requires no special configuration when using DUB to manage your project. There is no link-time dependency. At runtime, the GnuTLS shared library is required to be on the shared library search path of the user's system. On Windows, this is typically handled by distributing the GnuTLS DLL with your program. On other systems, it usually means the user must install the GnuTLS runtime library through a package manager.

To load the shared library, you need to call the `loadGnuTLS` function. This returns a member of the `GnuTLSSupport` enumeration (See [the README for `bindbc.loader`](https://github.com/BindBC/bindbc-loader/blob/master/README.md) for the error handling API):

* `GnuTLSSupport.noLibrary` indicating that the library failed to load (it couldn't be found)
* `GnuTLSSupport.badLibrary` indicating that one or more symbols in the library failed to load
* `GnuTLSSupport.xxx` indicating that GnuTLS has been successfully loaded in with a minimal required version.

Same applies to GnuTLS Dane, just use `loadGnuTLS_Dane` for that.

```D
import core.stdc.stdio;
import bindbc.gnutls;
import loader = bindbc.loader.sharedlib;

auto res = loadGnuTLS();
if (res != LoadRes.loaded)
{
    printf("Error loading GnuTLS: %d\n", res);
    foreach(info; loader.errors)
    {
        printf("\t%s: %s\n", info.error, info.message);
    }
    assert(0);
}
```

### The static binding

The static binding has a link-time dependency on either the shared or the static GnuTLS library. On Windows, you can link with the static library or, to use the shared library (libgnutls-30.dll), with the import library. On other systems, you can link with either the static library or directly with the shared library. This requires the GnuTLS development package be installed on your system at compile time, either by compiling the GnuTLS source yourself, downloading the GnuTLS precompiled binaries for Windows, or installing via a system package manager. See the GnuTLS documentation for details.

When linking with the static library, there is no runtime dependency on GnuTLS. When linking with the shared library (or the import library on Windows), the runtime dependency is the same as the dynamic binding, the difference being that the shared library is no longer loaded manually---loading is handled automatically by the system when the program is launched.

Enabling the static binding can be done in two ways.

### Via the compiler's `-version` switch or DUB's `versions` directive

Pass the `BindGnuTLS_Static` version to the compiler and link with the appropriate library.

When using the compiler command line or a build system that doesn't support DUB, this is the only option. The `-version=BindGnuTLS_Static` option should be passed to the compiler when building your program. All of the required C libraries, as well as the `bindbc-gnutls` and `bindbc-loader` static libraries must also be passed to the compiler on the command line or via your build system's configuration (see `tests/run.sh` for some examples).

When using DUB, its `versions` directive is an option. For example, when using the static binding:

#### dub.json

```JSON
"dependencies": {
    "bindbc-gnutls": "~>1.0.0"
},
"versions": ["BindGnuTLS_Static"],
"libs": ["gnutls"]
```

#### dub.sdl

```SDL
dependency "bindbc-gnutls" version="~>1.0.0"
versions "BindGnuTLS_Static"
libs "gnutls"
```

### Via DUB subconfigurations

Instead of using DUB's `versions` directive, a `subConfiguration` can be used. Enable the `static` subconfiguration for the `bindbc-gnutls` dependency:

#### dub.json

```JSON
"dependencies": {
    "bindbc-gnutls": "~>1.0.0"
},
"subConfigurations": {
    "bindbc-gnutls": "static"
},
"libs": ["gnutls"]
```

#### dub.sdl

```SDL
dependency "bindbc-gnutls" version="~>1.0.0"
subConfiguration "bindbc-gnutls" "static"
libs "gnutls"
```

This has the benefit that it completely excludes from the build any source modules related to the dynamic binding, i.e. they will never be passed to the compiler.

## `betterC` support

`betterC` support is enabled via the `dynamicBC` and `staticBC` subconfigurations, for dynamic and static bindings respectively. To enable the static binding with `-betterC` support:

### dub.json

```JSON
"dependencies": {
    "bindbc-gnutls": "~>1.0.0"
},
"subConfigurations": {
    "bindbc-gnutls": "staticBC"
},
"libs": ["gnutls"]
```

### dub.sdl

```SDL
dependency "bindbc-gnutls" version="~>1.0.0"
subConfiguration "bindbc-gnutls" "staticBC"
libs "gnutls"
```

When not using DUB to manage your project, first use DUB to compile the BindBC libraries with the `dynamicBC` or `staticBC` configuration, then pass `-betterC` to the compiler when building your project.
