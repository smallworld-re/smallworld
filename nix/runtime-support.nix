# Runtime and shell assembly for the main SmallWorld flake.
#
# The Python package graph lives in `python-packages.nix`. This module takes
# that graph and turns it into the things users interact with:
#   - `nix develop`
#   - `nix build`
#   - downstream helper functions like `smallworld.lib.mkPython`
#
# If you are new to Nix, this file answers:
# "How do the raw packages become a usable shell or runtime environment?"
{
  lib,
  inputs,
  mkLockedVirtualenv,
  mkPythonSet,
  mkSmallworldPythonModule,
  pkgsFor,
  pythonFor,
  pythonSets,
  runtimeSelection,
  devSelection,
}:

let
  binaryninja = inputs.binaryninja or null;
  binjaZip = inputs.binjaZip or null;

  ghidraInstallDir = ghidra: "${ghidra}/lib/ghidra";

  # Ghidra is the only tool in the regular runtime that needs both binaries on
  # PATH and matching environment variables in every shell/program wrapper.
  mkGhidraRuntime = pkgs: {
    tools = [
      pkgs.ghidra
      pkgs.jdk
    ];

    env = {
      GHIDRA_INSTALL_DIR = ghidraInstallDir pkgs.ghidra;
      JAVA_HOME = pkgs.jdk;
    };

    setupHook = ''
      export GHIDRA_INSTALL_DIR=${ghidraInstallDir pkgs.ghidra}
      export JAVA_HOME=${pkgs.jdk}
    '';
  };

  runtimeToolsFor =
    system:
    let
      pkgs = pkgsFor system;
      ghidra = mkGhidraRuntime pkgs;
    in
    # afl++ is not packaged for Apple Silicon macOS.
    lib.optional (system != "aarch64-darwin") pkgs.aflplusplus ++ [ pkgs.z3 ] ++ ghidra.tools;

  # `buildEnv` is how we merge several derivations into one user-facing
  # environment. The extra setup-hook plumbing below is what keeps PATH,
  # PYTHONPATH, JAVA_HOME, and similar shell state working after the merge.
  mkBuildEnvWithHook =
    {
      pkgs,
      name,
      paths,
      setupHookInputs ? [ ],
      extraSetupHook ? "",
      extraPostBuild ? "",
      pathsToLink ? [
        "/bin"
        "/nix-support"
      ],
      nativeBuildInputs ? [ ],
    }:
    pkgs.buildEnv {
      inherit
        name
        paths
        pathsToLink
        nativeBuildInputs
        ;
      ignoreCollisions = true;

      postBuild = ''
        if [ -L "$out/nix-support" ]; then rm -f "$out/nix-support"; fi
        mkdir -p "$out/nix-support"
        if [ -e "$out/nix-support/setup-hook" ]; then rm -f "$out/nix-support/setup-hook"; fi
        : > "$out/nix-support/setup-hook"
      ''
      + lib.concatMapStrings (hookInput: ''
        if [ -f "${hookInput}/nix-support/setup-hook" ]; then
          cat "${hookInput}/nix-support/setup-hook" >> "$out/nix-support/setup-hook"
        fi
      '') setupHookInputs
      + lib.optionalString (extraSetupHook != "") ''
        cat >> "$out/nix-support/setup-hook" <<'EOF'
        ${extraSetupHook}
        EOF
      ''
      + extraPostBuild;
    };

  # Start from a locked SmallWorld Python environment and optionally layer a
  # few ordinary nixpkgs Python packages on top. This is the shared base for
  # both the default runtime and downstream helper envs.
  mkAugmentedPythonEnv =
    {
      system,
      name,
      basePythonEnv,
      extraPythonPackages ? (_: [ ]),
      python ? pythonFor system,
    }:
    let
      pkgs = pkgsFor system;
      extraPython = extraPythonPackages python.pkgs;
      extraPythonEnv = if extraPython == [ ] then null else python.withPackages (_: extraPython);
    in
    if extraPythonEnv == null then
      basePythonEnv
    else
      mkBuildEnvWithHook {
        inherit pkgs name;
        paths = [
          basePythonEnv
          extraPythonEnv
        ];
        setupHookInputs = [ basePythonEnv ];
        extraSetupHook = ''
          export PYTHONPATH=${extraPythonEnv}/${python.sitePackages}''${PYTHONPATH:+:$PYTHONPATH}
        '';
      };

  # Add the standard SmallWorld native toolchain to a Python environment.
  mkRuntimeEnv =
    {
      system,
      name,
      pythonEnv,
      extraPackages ? [ ],
      extraSetupHook ? "",
    }:
    let
      pkgs = pkgsFor system;
      ghidra = mkGhidraRuntime pkgs;
    in
    mkBuildEnvWithHook {
      inherit pkgs name;
      paths = [ pythonEnv ] ++ runtimeToolsFor system ++ extraPackages;
      setupHookInputs = [ pythonEnv ];
      extraSetupHook = ghidra.setupHook + extraSetupHook;
    };

  # Root packages and downstream envs both come from the same assembly path:
  # locked Python env first, then runtime tools, then any caller extras.
  mkLockedRuntimeEnv =
    {
      system,
      name,
      selection,
      extraPythonPackages ? (_: [ ]),
      extraPackages ? [ ],
    }:
    let
      pythonEnv = mkAugmentedPythonEnv {
        inherit system extraPythonPackages;
        name = "${name}-python";
        basePythonEnv = mkLockedVirtualenv system "${name}-locked-python" selection;
      };
    in
    mkRuntimeEnv {
      inherit
        system
        name
        pythonEnv
        extraPackages
        ;
    };

  mkDownstreamEnv =
    {
      system,
      name ? "smallworld-re-env",
      extraPythonPackages ? (_: [ ]),
      extraPackages ? [ ],
    }:
    mkLockedRuntimeEnv {
      inherit
        system
        name
        extraPythonPackages
        extraPackages
        ;
      selection = runtimeSelection;
    };

  mkDownstreamShell =
    {
      system,
      name ? "smallworld-shell",
      extraPythonPackages ? (_: [ ]),
      extraPackages ? [ ],
      packages ? [ ],
      env ? { },
      shellHook ? "",
    }:
    let
      pkgs = pkgsFor system;
      runtimeEnv = mkDownstreamEnv {
        inherit system extraPythonPackages extraPackages;
        name = "${name}-env";
      };
    in
    pkgs.mkShell {
      packages = [ runtimeEnv ] ++ packages;
      inherit env shellHook;
    };

  defaultMkPythonExtras =
    python:
    [
      "emu-ghidra"
      "emu-panda"
      "emu-unicorn"
    ]
    ++ lib.optional (lib.versionAtLeast python.pythonVersion "3.10") "emu-angr";

  mkPythonRuntimeSupport =
    {
      pkgs,
      smallworldExtras,
    }:
    let
      ghidra = mkGhidraRuntime pkgs;
      needsGhidra = builtins.elem "emu-ghidra" smallworldExtras;
    in
    {
      paths = lib.optionals needsGhidra ghidra.tools;
      env = lib.optionalAttrs needsGhidra ghidra.env;
      setupHook = lib.optionalString needsGhidra ghidra.setupHook;
      nativeBuildInputs = lib.optionals needsGhidra [ pkgs.makeWrapper ];

      extraPostBuild = lib.optionalString needsGhidra ''
        for program in "$out"/bin/*; do
          if [ -f "$program" ] && [ -x "$program" ]; then
            wrapProgram "$program" \
              --set-default GHIDRA_INSTALL_DIR ${ghidra.env.GHIDRA_INSTALL_DIR} \
              --set-default JAVA_HOME ${ghidra.env.JAVA_HOME}
          fi
        done
      '';
    };

  # Build a Python interpreter whose `python.pkgs` set exposes `smallworld`
  # without requiring downstream callers to install a global nixpkgs overlay.
  # This is the main user-facing helper API for other flakes.
  mkDownstreamPython =
    {
      pkgs,
      system ? pkgs.stdenv.hostPlatform.system,
      python ? pythonFor system,
      smallworldExtras ? defaultMkPythonExtras python,
      packageOverrides ? (_: _: { }),
    }:
    let
      runtimeSupport = mkPythonRuntimeSupport {
        inherit pkgs smallworldExtras;
      };

      pythonSet = mkPythonSet {
        inherit system pkgs python;
      };

      pythonWithSmallworld = python.override {
        packageOverrides = lib.composeExtensions (
          py-final: _py-prev:
          let
            smallworldModule = mkSmallworldPythonModule {
              inherit pythonSet py-final smallworldExtras;
            };
          in
          {
            smallworld = smallworldModule;
            "smallworld-re" = smallworldModule;
          }
        ) packageOverrides;
      };
    in
    pythonWithSmallworld
    // {
      withPackages =
        packageSelector:
        let
          baseEnv = pythonWithSmallworld.withPackages packageSelector;
        in
        mkBuildEnvWithHook {
          inherit pkgs;
          name = baseEnv.name;
          paths = [ baseEnv ] ++ runtimeSupport.paths;
          pathsToLink = [ "/" ];
          setupHookInputs = [ baseEnv ];
          extraSetupHook = runtimeSupport.setupHook;
          nativeBuildInputs = runtimeSupport.nativeBuildInputs;
          extraPostBuild = runtimeSupport.extraPostBuild;
        };
    };

  mkDownstreamPythonShell =
    {
      pkgs,
      system ? pkgs.stdenv.hostPlatform.system,
      python ? pythonFor system,
      smallworldExtras ? defaultMkPythonExtras python,
      packageOverrides ? (_: _: { }),
      extraPythonPackages ? (_: [ ]),
      packages ? [ ],
      env ? { },
      shellHook ? "",
    }:
    let
      runtimeSupport = mkPythonRuntimeSupport {
        inherit pkgs smallworldExtras;
      };

      smallworldPython = mkDownstreamPython {
        inherit
          pkgs
          system
          python
          smallworldExtras
          packageOverrides
          ;
      };

      pythonEnv = smallworldPython.withPackages (ps: [ ps.smallworld ] ++ extraPythonPackages ps);
    in
    pkgs.mkShell {
      packages = [ pythonEnv ] ++ packages;
      env = runtimeSupport.env // env;
      inherit shellHook;
    };

  binaryNinjaFor =
    system:
    if binaryninja != null && binjaZip != null then
      let
        binaryNinjaPackages = binaryninja.packages.${system};
      in
      binaryNinjaPackages.binary-ninja-ultimate-wayland.override {
        overrideSource = binjaZip;
      }
    else
      null;

  mkDeveloperShell =
    system:
    let
      pkgs = pkgsFor system;
      binaryNinja = binaryNinjaFor system;
      runtimeEnv = mkLockedRuntimeEnv {
        inherit system;
        name = "smallworld-re-dev-env";
        selection = devSelection;
        extraPythonPackages = ps: [ ps.coverage ];
      };
    in
    pkgs.mkShell {
      packages = [
        runtimeEnv
        # The shellHook below uses `git rev-parse` to find the repo root.
        pkgs.git
        pkgs.uv
        pkgs.nixfmt
        pkgs.nixfmt-tree
      ]
      ++ lib.optional (binaryNinja != null) binaryNinja;

      hardeningDisable = [ "all" ];

      shellHook = ''
        # Let package setup hooks populate PYTHONPATH. Clearing it here breaks
        # layered developer-only modules like `coverage`.
        export REPO_ROOT=$(git rev-parse --show-toplevel)
        ${lib.optionalString (binaryNinja != null) "export BINJA_PATH=${binaryNinja}"}
        # Keep the live checkout ahead of the locked Nix environment so source
        # edits are reflected immediately in the developer shell.
        export PYTHONPATH=$REPO_ROOT${
          lib.optionalString (binaryNinja != null) ":${binaryNinja}/opt/binaryninja/python"
        }''${PYTHONPATH:+:$PYTHONPATH}
      '';
    };

  mkPackageOutputs =
    system:
    let
      pkgs = pkgsFor system;
      pythonSet = pythonSets.${system};
      binaryNinja = binaryNinjaFor system;

      lockedRuntimePython = mkLockedVirtualenv system "smallworld-re-env" runtimeSelection;
      runtimeEnv = mkDownstreamEnv {
        inherit system;
        name = "smallworld-re-env";
      };
    in
    {
      # `nix build` with no target builds the full runtime environment.
      default = runtimeEnv;

      # Build just the Python package artifact with:
      #   nix build .#smallworld-re
      "smallworld-re" = pythonSet.smallworld-re;

      dockerImage =
        let
          hasBinaryNinja = binaryNinja != null;
        in
        pkgs.dockerTools.buildImage {
          name = "smallworld-re";
          tag = "latest";

          copyToRoot = pkgs.buildEnv {
            name = "smallworld-root";
            paths = [
              pkgs.dockerTools.usrBinEnv
              pkgs.dockerTools.binSh
              pkgs.dockerTools.caCertificates
              pkgs.dockerTools.fakeNss
              pkgs.coreutils
              pkgs.unzip
              pkgs.dbus.lib
              pkgs.stdenv.cc.cc.lib
              lockedRuntimePython
            ]
            ++ runtimeToolsFor system
            ++ lib.optional hasBinaryNinja binaryNinja;

            pathsToLink = [
              "/bin"
              "/etc"
              "/var"
              "/lib"
            ]
            ++ lib.optional hasBinaryNinja "/opt";
          };

          config = {
            Cmd = [ "/bin/sh" ];
            Env = [
              "LD_LIBRARY_PATH=/lib"
              "GHIDRA_INSTALL_DIR=${ghidraInstallDir pkgs.ghidra}"
              "JAVA_HOME=${pkgs.jre}"
            ];
          };
        };
    }
    // lib.optionalAttrs (binaryNinja != null) {
      binaryninja-ultimate = binaryNinja;
    };
in
{
  inherit
    mkDeveloperShell
    mkDownstreamPython
    mkDownstreamPythonShell
    mkPackageOutputs
    ;
}
