# ripasso
A simple password manager written in Rust

This is a reimplementation of https://github.com/cortex/gopass in Rust. I started it mainly because since https://github.com/go-qml/qml
is unmaintaned. Also, using a safe language for you passwords seems like a good idea. 

It has not yet reached feature-parity, but the basic functionality works. If this plays out well, it will replace gopass.

PRs are very welcome!

## Quick Start

### Mac OS X

*steps may be incomplete*

```
$ brew update
$ brew install automake cmake qt5
$ export PATH="/usr/local/opt/qt/bin:$PATH"
$ git clone https://github.com/cortex/ripasso.git
$ cd ripasso
$ cargo run
```
