# a non-flake nix compat wrapper using https://github.com/edolstra/flake-compat
# DO NOT EDIT THIS FILE
__trace
     ''************************************************************************************
        Hi there! This project has been moved to nix flakes. You are using the `nix-shell`
        compatibility layer. Please consider using `nix develop` instead.
       ************************************************************************************
''
(import
  (
    let lock = builtins.fromJSON (builtins.readFile ./flake.lock); in
    fetchTarball {
      url = "https://github.com/edolstra/flake-compat/archive/${lock.nodes.flake-compat.locked.rev}.tar.gz";
      sha256 = lock.nodes.flake-compat.locked.narHash;
    }
  )
  { src = ./.; }
).shellNix
