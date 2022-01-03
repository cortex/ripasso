# Build instructions

## Build dependencies

Ripasso depends on a number of local libraries through it's dependencies:

 * ncurses
 * python3
 * openssl
 * libgpgerror
 * gpgme
 * xorg

They are named different things on different platforms

### Mac OS X

```
$ brew update
$ brew install automake cmake gettext qt5 gtk+3 gpgme
$ export PATH="/usr/local/opt/qt/bin:$PATH"
$ git clone https://github.com/cortex/ripasso.git
$ cd ripasso
$ cargo run
```

### Ubuntu
```
$ apt install cargo libgtk-3-dev qtdeclarative5-dev libqt5svg5-dev cmake libncurses-dev libncursesw5-dev libssl-dev libgpgme-dev libxcb-xfixes0-dev libxcb-shape0-dev
$ cargo build --all
```

### Arch
```
$ pacman -S qt5-base qt5-svg qt5-declarative
```

### Alpine
#### Cursive
```
apk add cargo python3-dev ncurses libgpg-error-dev gpgme-dev openssl-dev libxcb-dev
```

### Fedora
#### All
```
$ dnf install cargo gpgme-devel openssl-devel
```
#### GTK
```
$ dnf install rust-gdk-devel
```
#### QML
```
$ dnf install qt5-qtbase-devel qt5-qtdeclarative-devel qt5-qtsvg-devel qt5-qtquickcontrols
```
## Building

Perform the build with:
```
cargo build --all --frozen --release
```
The argument `--frozen` ensures that the content of the `Cargo.lock` file is respected so that the build is repeatable,
this is mostly of interest for package maintainers in distributions.

### Build artifacts

The build produces a number of artifacts:
 * `./target/release/ripasso-cursive` - the main application binary, with the ncurses TUI
 * `./target/release/ripasso-gtk` - the GTK application, still in an experimental phase and not really usable
 * `./target/release/ripasso-qt` - the QT application, still in an experimental phase and not really usable
 * `./target/man-page/cursive/ripasso-cursive.1` - The manual page for ripasso-cursive
 * `./target/translations/cursive/fr.mo` - french translation
 * `./target/translations/cursive/it.mo` - italian translation
 * `./target/translations/cursive/nb.mo` - norwegian bokmål translation
 * `./target/translations/cursive/nn.mo` - norwegian nynorsk translation
 * `./target/translations/cursive/sv.mo` - swedish translation

The translation files are in gettext binary format, and should be installed in `/usr/share/ripasso/`. If that location doesn't
conform to your distribution's guidelines, then you can supply the environmental variable `TRANSLATION_INPUT_PATH` when building to specify another.
