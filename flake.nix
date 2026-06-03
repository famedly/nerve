{
  description = "Example rust project to test the engineering standards.";

  inputs = {
    famedly-engineering-standards.url = "/home/lukas/engineering-standards";

    nixpkgs.follows = "famedly-engineering-standards/nixpkgs";
    flake-parts.follows = "famedly-engineering-standards/flake-parts";
  };

  outputs =
    { famedly-engineering-standards, flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ famedly-engineering-standards.flakeModules.default ];

      systems = [ "x86_64-linux" ];

      perSystem.famedly.standards.rust.projects."." = { };
    };
}
