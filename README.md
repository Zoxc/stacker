# stacker

[![Build Status](https://travis-ci.org/alexcrichton/stacker.svg?branch=master)](https://travis-ci.org/alexcrichton/stacker)
[![Build status](https://ci.appveyor.com/api/projects/status/1yca9gp2bhe9h2by?svg=true)](https://ci.appveyor.com/project/alexcrichton/stacker)

[Documentation](http://alexcrichton.com/stacker)

A stack-growth library for Rust. Enables annotating fixed points in programs
where the stack may want to grow larger. Spills over to the heap if the stack
has hit its limit.

This library is intended on helping implement recursive algorithms.

```toml
# Cargo.toml
[dependencies]
stacker = "0.1"
```

## Platform Support

This library currently is verified to work on the following platforms:

* 32/64 bit Linux
* 32/64 bit OSX
* 32/64 bit MinGW Windows
* 32/64 bit MSVC Windows

# License

`stacker` is primarily distributed under the terms of both the MIT license and
the Apache License (Version 2.0), with portions covered by various BSD-like
licenses.

See LICENSE-APACHE, and LICENSE-MIT for details.
