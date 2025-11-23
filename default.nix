{
  rustPlatform,
  glib,
  pkg-config,
}:
rustPlatform.buildRustPackage {
  name = "ripasso";
  src = ./.;
  buildInputs = [ glib ];
  nativeBuildInputs = [ pkg-config ];
  cargoHash = "sha256-UMhQgijZuZW2O/0Jk5Zn8P368KnDWZRXj5e1nDG40Gw=";
} 
