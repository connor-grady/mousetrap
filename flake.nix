{
  inputs = {
    flake-parts = {
      url = "flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    nixpkgs.url = "nixpkgs";
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    systems.url = "github:nix-systems/default-linux";
  };

  outputs =
    inputs:
    let
      inherit (inputs.flake-parts.lib) mkFlake;
      inherit (inputs.pyproject-nix.lib.project) loadRequirementsTxt;
    in
    mkFlake { inherit inputs; } {
      systems = import inputs.systems;
      perSystem = { pkgs, ... }: {
        devShells.default = pkgs.mkShellNoCC {
          name = "mousetrap";
          packages = [
            (
              loadRequirementsTxt { projectRoot = ./backend; }
              |> (r: r.renderers.withPackages { python = pkgs.python3; })
              |> pkgs.python3.withPackages
            )
          ];
        };
      };
    };
}
