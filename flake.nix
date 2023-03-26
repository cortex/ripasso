{
  inputs = {
    naersk.url = "github:nix-community/naersk/master";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils, naersk }:

    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = pkgs.callPackage naersk { };
      in
      {
      formatter.x86_64-linux = nixpkgs.legacyPackages.nixfmt;
        defaultPackage = naersk-lib.buildPackage ./.;
        devShell = with pkgs; mkShell {
                  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang}/lib/libclang.so";

          nativeBuildInputs = [
            openssl
            pkg-config
          ];
          
          # necessary to override nix's defaults which cannot be overriden as others are
          shellHook = ''
            export CC="${pkgs.clang}/bin/clang"
            export CXX="${pkgs.clang}/bin/clang++"
            export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
            rustup override set stable
            '';
                  
          buildInputs = [
             cargo
             rustc
             rustfmt
             pre-commit
             rustPackages.clippy
             openssl
             pkg-config
             libgpg-error
            clang
            nettle
            libclang
            gpgme
            ];
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
        };
      });
}
