# Build instructions

## Build dependencies

Ripasso depends on a number of local libraries through it's dependencies:

 * openssl - for git operations
 * libgit2 - for git operations
 * libgpgerror - for the gpgme encryption backend
 * gpgme - for the gpgme encryption backend
 * xorg - for the clippboard
 * nettle-dev - for the sequoia encryption backend

They are named different things on different platforms

### Mac OS X

```
$ brew update
$ brew install automake cmake gettext gtk+4 gpgme
$ git clone https://github.com/cortex/ripasso.git
$ cd ripasso
$ cargo run
```

### Ubuntu
```
$ apt install cargo libssl-dev libclang-dev libadwaita-1-dev libgpgme11-dev libgpg-error-dev libgtk-4-dev libxcb-shape0-dev libxcb-xfixes0-dev nettle-dev
$ cargo build --all
```

### Fedora
#### All
```
$ dnf install cargo gpgme-devel openssl-devel libxcb libxcb-devel nettle-devel
```
#### GTK
```
$ dnf install rust-gdk-devel
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
 * `./target/release/ripasso-cursive` - the main application binary, with the curses TUI
 * `./target/release/ripasso-gtk` - the GTK application, still in an experimental phase
 * `./target/man-page/cursive/ripasso-cursive.1` - The manual page for ripasso-cursive
 * `./target/translations/cursive/de.mo` - german translation
 * `./target/translations/cursive/fr.mo` - french translation
 * `./target/translations/cursive/it.mo` - italian translation
 * `./target/translations/cursive/nb.mo` - norwegian bokmål translation
 * `./target/translations/cursive/nn.mo` - norwegian nynorsk translation
 * `./target/translations/cursive/sv.mo` - swedish translation

The translation files are in gettext binary format, and should be installed in
`/usr/share/locale/{}/LC_MESSAGES/ripasso-cursive.mo` where `{}` should be replaced
with the locale. If that location doesn't conform to your distribution's guidelines,
then you can supply the environmental variable `TRANSLATION_INPUT_PATH` when building
to specify another.
