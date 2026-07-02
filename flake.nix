{
  description = "Example rust project to test the engineering standards.";

  inputs = {
    famedly-engineering-standards.url = "/home/lukas/engineering-standards";

    nixpkgs.follows = "famedly-engineering-standards/nixpkgs";
    flake-parts.follows = "famedly-engineering-standards/flake-parts";
    rust-overlay.follows = "famedly-engineering-standards/rust-overlay";
  };

  outputs =
    { famedly-engineering-standards, flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ famedly-engineering-standards.flakeModules.default ];

      systems = [ "x86_64-linux" ];

      perSystem =
        { lib, pkgs, ... }:
        {
          famedly.standards.rust.projects."." = { };

          # C compiler/linker needed by cargo to link build scripts and crates.
          # Python with numpy/matplotlib for plot_delivery_cdf.py.
          devshells.rust.packages = [
            pkgs.stdenv.cc
            (pkgs.python3.withPackages (ps: [
              ps.numpy
              ps.matplotlib
            ]))
          ];

          # Pinned to 1.93 due to
          # https://github.com/matrix-org/matrix-rust-sdk/issues/6254
          packages.famedly-rust-toolchain = lib.mkForce
            (inputs.rust-overlay.lib.mkRustBin { } pkgs.buildPackages).stable."1.93.0".default;
        };
    };
}
