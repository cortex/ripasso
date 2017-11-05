# ripasso
[![Build Status](https://travis-ci.org/cortex/ripasso.svg?branch=master)](https://travis-ci.org/cortex/ripasso)


A simple password manager written in Rust

This is a reimplementation of https://github.com/cortex/gopass in Rust. I started it mainly because since https://github.com/go-qml/qml
is unmaintaned. Also, using a safe language for you passwords seems like a good idea. 

It has not yet reached feature-parity, but the basic functionality works. If this plays out well, it will replace gopass.

PRs are very welcome!

Build Instructions on ubuntu:

    apt install cargo libgtk-3-dev qtdeclarative5-dev libqt5svg5-dev cmake
    cargo build

