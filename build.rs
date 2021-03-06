extern crate gcc;

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();
    let msvc = target.contains("msvc");

    let mut cfg = gcc::Config::new();

    if target.contains("linux") {
        cfg.define("LINUX", None);
    } else if target.contains("darwin") {
        cfg.define("APPLE", None);
    } else if target.contains("windows") {
        cfg.define("WINDOWS", None);
    } else {
        panic!("\n\nusing currently unsupported target triple with \
                stacker: {}\n\n", target);
    }

    if target.starts_with("x86_64") {
        cfg.file(if msvc {"src/arch/x86_64.asm"} else {"src/arch/x86_64.S"});
        cfg.define("X86_64", None);
    } else if target.contains("i686") {
        cfg.file(if msvc {"src/arch/i686.asm"} else {"src/arch/i686.S"});
        cfg.define("X86", None);
    } else {
        panic!("\n\nusing currently unsupported target triple with \
                stacker: {}\n\n", target);
    }

    cfg.include("src/arch").compile("libstacker.a");
}
