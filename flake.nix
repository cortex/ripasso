{
  inputs = {
    nixpkgs.url = "github:cachix/devenv-nixpkgs/rolling";
    devenv.url = "github:cachix/devenv";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs = { nixpkgs.follows = "nixpkgs"; };
  };

  nixConfig = {
    extra-trusted-public-keys = "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=";
    extra-substituters = "https://devenv.cachix.org";
  };

  outputs = { self, nixpkgs, devenv, ... } @ inputs:
    let
      system = "aarch64-darwin";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system}.devenv-up = self.devShells.${system}.default.config.procfileScript;
      #packages.${system}.devenv-test = self.devShells.${system}.default.config.test;

      devShells.${system}.default = devenv.lib.mkShell {
        inherit inputs pkgs;
        modules = [
          ({ pkgs, config, ... }: {
            # This is your devenv configuration

            languages.rust = {
              enable = true;
              # https://devenv.sh/reference/options/#languagesrustchannel
              channel = "stable";

              components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" ]; /* "miri" doesn't work on stable */
            };

            packages = [
              # Native build tools
              pkgs.pkg-config          # locate the C libraries below
              pkgs.cmake               # libgit2-sys vendored build
              pkgs.capnproto           # `capnp` for sequoia-ipc build.rs
              pkgs.gettext             # `msgfmt` for cursive translation files
              pkgs.llvmPackages.libclang # bindgen (gpgme-sys / nettle-sys)

              # C libraries every crate links against
              pkgs.openssl             # git2 / reqwest (native-tls)
              pkgs.libgit2             # git operations
              pkgs.gpgme               # gpgme encryption backend
              pkgs.libgpg-error        # gpgme encryption backend
              pkgs.nettle              # sequoia encryption backend
              pkgs.glib                # gtk / gio

              # GTK front-end (ripasso-gtk)
              pkgs.gtk4
              pkgs.libadwaita

              # Runtime tool used by the gpgme test-suite
              pkgs.gnupg
            ];

            env = {
              EDITOR = "emacs -nw ";
              # Link against the nixpkgs OpenSSL instead of vendoring it.
              OPENSSL_NO_VENDOR = "1";
              # bindgen (gpgme-sys, nettle-sys) needs to find libclang.
              LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            };

            # Convenience commands: `build-all` and `test-all`.
            scripts.build-all.exec = "cargo build --all";
            scripts.test-all.exec = "cargo test --all";
          })
        ];
      };
    };
}
