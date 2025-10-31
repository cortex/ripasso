{
  description = "Rust flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }@inputs:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      clangLibPath = "${pkgs.libclang.lib}/lib";
      opensslDev = pkgs.openssl.dev;
      opensslOut = pkgs.openssl.out;
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          rustc
          cargo
          clang
          libclang
          openssl
          pkg-config
          libgpg-error
          nettle
          gpgme
          ripasso-cursive
        ];

        shellHook = ''
          # Clang
          export LIBCLANG_PATH=${clangLibPath}
          export LD_LIBRARY_PATH=${clangLibPath}:${opensslOut}/lib:$LD_LIBRARY_PATH

          # OpenSSL
          export OPENSSL_NO_VENDOR=1
          export OPENSSL_LIB_DIR=${opensslOut}/lib
          export OPENSSL_INCLUDE_DIR=${opensslDev}/include

          echo "🔧 Environment configured:"
          echo "  LIBCLANG_PATH         = $LIBCLANG_PATH"
          echo "  LD_LIBRARY_PATH       = $LD_LIBRARY_PATH"
          echo "  OPENSSL_LIB_DIR       = $OPENSSL_LIB_DIR"
          echo "  OPENSSL_INCLUDE_DIR   = $OPENSSL_INCLUDE_DIR"
          echo "🚀 Welcome to the Rust dev shell"
        '';
      };
    };
}
