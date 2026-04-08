# Nix flake for smallworld-re.
#
# Reader's guide:
# 1. Read `pyproject.toml` + `uv.lock` and turn them into Nix packages.
# 2. Replace the few Python dependencies that need native compilation.
# 3. Assemble the environments and shells users actually interact with.
# 4. Export a small helper library for downstream flakes.
#
# If you are new to Nix, the most important idea is:
# "inputs" says what external code we depend on, and "outputs" says what
# commands like `nix build`, `nix develop`, and downstream flakes can use.
{
  description = "smallworld-re";

  # External inputs. `follows` means "reuse the parent's copy" so we do not
  # accidentally pull in multiple versions of the same dependency tree.
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # PANDA-ng provides the pypanda Python bindings.
    panda-ng = {
      url = "github:panda-re/panda-ng";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Optional Binary Ninja support (uncomment both to enable).
    # binaryninja = {
    #   url = "github:jchv/nix-binary-ninja";
    #   inputs.nixpkgs.follows = "nixpkgs";
    # };
    # binjaZip = {
    #   url = "path:./binaryninja_linux_stable_ultimate.zip";
    #   flake = false;
    # };
  };

  outputs =
    inputs@{
      nixpkgs,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      panda-ng,
      ...
    }:
    let
      lib = nixpkgs.lib;

      # -------------------------------------------------------------------
      # Basic helpers used everywhere else in the file.
      # -------------------------------------------------------------------

      supportedSystems = lib.systems.flakeExposed;
      forEachSystem = lib.genAttrs supportedSystems;

      pkgsFor = system: nixpkgs.legacyPackages.${system};
      pythonFor = system: (pkgsFor system).python312;

      binaryninja = inputs.binaryninja or null;
      binjaZip = inputs.binjaZip or null;

      ghidraInstallDir = ghidra: "${ghidra}/lib/ghidra";

      # Small helper for the two environment variables Ghidra expects.
      mkGhidraRuntime =
        pkgs:
        {
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

      # -------------------------------------------------------------------
      # Read the Python workspace.
      #
      # We only copy the files that influence the Python package graph. That
      # keeps unrelated edits from forcing a full rebuild.
      # -------------------------------------------------------------------

      workspaceRoot =
        let
          fileset = lib.fileset.unions [
            ./pyproject.toml
            ./uv.lock
            ./.python-version
            ./smallworld
          ];
        in
        /.
        + builtins.unsafeDiscardStringContext (
          lib.fileset.toSource {
            inherit fileset;
            root = ./.;
          }
        );

      workspace = uv2nix.lib.workspace.loadWorkspace { inherit workspaceRoot; };

      selectWorkspaceDeps =
        extras:
        workspace.deps.default
        // {
          smallworld-re = extras;
        };

      # The published runtime wants every emulator backend. The development
      # shell adds the project's `dev` dependency group on top.
      runtimeSelection = selectWorkspaceDeps [ "emu-all" ];
      devSelection = selectWorkspaceDeps ([ "emu-all" ] ++ workspace.deps.groups.smallworld-re);

      # These packages are built locally below, so we hand uv2nix empty
      # placeholders to stop it from also trying to fetch them from PyPI.
      prebuiltPythonPackages = [
        "unicornafl"
        "pypanda"
        "unicorn"
      ];

      addPrebuiltPlaceholders =
        deps: deps // lib.genAttrs prebuiltPythonPackages (_: [ ]);

      # -------------------------------------------------------------------
      # Build the Python packages that cannot safely come from wheels.
      # -------------------------------------------------------------------

      mkNativePythonAddons =
        {
          system,
          pythonPkgs,
          unicornPy,
          pkgs ? pkgsFor system,
        }:
        let
          mkUnicornafl = pkgs.callPackage ./unicornafl-build { };
          patchedUnicornSrc = pkgs.fetchFromGitHub {
            owner = "appleflyerv3";
            repo = "unicorn";
            rev = "mmio_map_pc_sync";
            hash = "sha256-0MH+JS/mPESnTf21EOfGbuVrrrxf1i8WzzwzaPeCt1w=";
          };
          patchedUnicorn = pkgs.unicorn.overrideAttrs (_: {
            src = patchedUnicornSrc;
          });
        in
        {
          unicorn = unicornPy.override { unicorn = patchedUnicorn; };
          unicornafl = mkUnicornafl pythonPkgs;
          pypanda = panda-ng.lib.${system}.pypandaBuilder pythonPkgs;
        };

      # Build the locked Python package set for one system/interpreter.
      #
      # Order matters here:
      # 1. start from pyproject/uv metadata,
      # 2. add standard build backends,
      # 3. apply our local package overrides,
      # 4. replace a few packages with the native builds above.
      mkPythonSet =
        {
          system,
          pkgs ? pkgsFor system,
          python ? pythonFor system,
        }:
        let
          pyprojectPackages = pkgs.callPackage pyproject-nix.build.packages { inherit python; };
          pyprojectHacks = pkgs.callPackage pyproject-nix.build.hacks { };

          nativeAddons = mkNativePythonAddons {
            inherit system pkgs;
            pythonPkgs = python.pkgs;
            unicornPy = python.pkgs.unicorn;
          };

          prebuiltOverlay = _final: _prev: {
            unicorn = pyprojectHacks.nixpkgsPrebuilt { from = nativeAddons.unicorn; };
            unicornafl = pyprojectHacks.nixpkgsPrebuilt { from = nativeAddons.unicornafl; };
            pypanda = pyprojectHacks.nixpkgsPrebuilt { from = nativeAddons.pypanda; };
          };
        in
        pyprojectPackages.overrideScope (
          lib.composeManyExtensions [
            pyproject-build-systems.overlays.wheel
            (workspace.mkPyprojectOverlay { sourcePreference = "wheel"; })
            (pkgs.callPackage ./overrides.nix { inherit python; })
            prebuiltOverlay
          ]
        );

      # Precompute once so the outputs below can reuse the same locked package
      # set instead of rebuilding the graph from scratch for every output.
      pythonSets = forEachSystem (system: mkPythonSet { inherit system; });

      # -------------------------------------------------------------------
      # Helpers for environments created from the locked Python package set.
      # -------------------------------------------------------------------

      resolveLockedDependencyNames =
        pythonSet: name: enabledExtras:
        let
          rawPackage = pythonSet.${name};
          selectedDeps =
            lib.zipAttrsWith (_depName: extrasLists: lib.unique (lib.flatten extrasLists)) (
              [ (rawPackage.dependencies or { }) ]
              ++ map (extra: rawPackage.optional-dependencies.${extra} or { }) enabledExtras
            );
          dependencyNames = builtins.attrNames selectedDeps;
        in
        lib.unique (
          dependencyNames
          ++ lib.flatten (
            map (
              dependencyName:
              resolveLockedDependencyNames pythonSet dependencyName selectedDeps.${dependencyName}
            ) dependencyNames
          )
        );

      # Turn the locked `smallworld-re` package into a Python module that
      # carries the transitive Python dependency closure expected by
      # `python.withPackages`.
      mkSmallworldPythonModule =
        {
          pythonSet,
          py-final,
          smallworldExtras,
        }:
        let
          rawSmallworld = pythonSet.smallworld-re;

          pypandaModule =
            if pythonSet ? pypanda then
              py-final.toPythonModule pythonSet.pypanda
            else
              null;

          dependencyNames =
            resolveLockedDependencyNames pythonSet "smallworld-re" smallworldExtras;

          dependencyModules =
            map (name: py-final.toPythonModule pythonSet.${name}) dependencyNames
            ++ lib.optional (
              builtins.elem "emu-panda" smallworldExtras && pypandaModule != null
            ) pypandaModule;
        in
        py-final.toPythonModule (
          rawSmallworld.overrideAttrs (old: {
            propagatedBuildInputs = (old.propagatedBuildInputs or [ ]) ++ dependencyModules;
          })
        );

      runtimeToolsFor =
        system:
        let
          pkgs = pkgsFor system;
          ghidra = mkGhidraRuntime pkgs;
        in
        # afl++ is not packaged for Apple Silicon macOS.
        lib.optional (system != "aarch64-darwin") pkgs.aflplusplus
        ++ [ pkgs.z3 ]
        ++ ghidra.tools;

      # Compose multiple derivations into one environment while preserving the
      # setup hooks they export. This is the main "glue" helper for the file.
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

          postBuild =
            ''
              if [ -L "$out/nix-support" ]; then rm -f "$out/nix-support"; fi
              mkdir -p "$out/nix-support"
              if [ -e "$out/nix-support/setup-hook" ]; then rm -f "$out/nix-support/setup-hook"; fi
              : > "$out/nix-support/setup-hook"
            ''
            + lib.concatMapStrings (
              hookInput: ''
                if [ -f "${hookInput}/nix-support/setup-hook" ]; then
                  cat "${hookInput}/nix-support/setup-hook" >> "$out/nix-support/setup-hook"
                fi
              ''
            ) setupHookInputs
            + lib.optionalString (extraSetupHook != "") ''
              cat >> "$out/nix-support/setup-hook" <<'EOF'
              ${extraSetupHook}
              EOF
            ''
            + extraPostBuild;
        };

      mkLockedVirtualenv =
        system: name: selection:
        pythonSets.${system}.mkVirtualEnv name (addPrebuiltPlaceholders selection);

      # This is the main runtime environment smallworld users interact with:
      # Python packages from the lockfile plus the native tools the project
      # expects to find on PATH.
      mkRuntimeEnv =
        {
          system,
          env,
          name ? "${env.name}-smallworld-full",
        }:
        let
          pkgs = pkgsFor system;
          ghidra = mkGhidraRuntime pkgs;
        in
        mkBuildEnvWithHook {
          inherit pkgs name;
          paths = [ env ] ++ runtimeToolsFor system;
          setupHookInputs = [ env ];
          extraSetupHook = ghidra.setupHook;
        };

      # Downstream flakes sometimes want the standard SmallWorld runtime plus a
      # few additional nixpkgs Python packages or shell tools.
      mkDownstreamEnv =
        {
          system,
          name ? "smallworld-re-env",
          extraPythonPackages ? (_: [ ]),
          extraPackages ? [ ],
        }:
        let
          pkgs = pkgsFor system;
          python = pythonFor system;

          lockedPythonEnv = mkLockedVirtualenv system "${name}-python" runtimeSelection;

          extraPython = extraPythonPackages python.pkgs;
          extraPythonEnv =
            if extraPython == [ ] then
              null
            else
              python.withPackages (_: extraPython);

          pythonEnv =
            if extraPythonEnv == null then
              lockedPythonEnv
            else
              mkBuildEnvWithHook {
                inherit pkgs;
                name = "${name}-python";
                paths = [
                  lockedPythonEnv
                  extraPythonEnv
                ];
                setupHookInputs = [ lockedPythonEnv ];
                extraSetupHook = ''
                  export PYTHONPATH=${extraPythonEnv}/${python.sitePackages}''${PYTHONPATH:+:$PYTHONPATH}
                '';
              };

          runtimeEnv = mkRuntimeEnv {
            inherit system name;
            env = pythonEnv;
          };
        in
        if extraPackages == [ ] then
          runtimeEnv
        else
          mkBuildEnvWithHook {
            inherit pkgs name;
            paths = [ runtimeEnv ] ++ extraPackages;
            setupHookInputs = [ runtimeEnv ];
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

      # -------------------------------------------------------------------
      # Helpers for downstream callers who prefer `python.withPackages`.
      # -------------------------------------------------------------------

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

      # Build a Python interpreter whose `python.pkgs` set exposes
      # `smallworld`, but without requiring the caller to import a global
      # nixpkgs overlay.
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

      # -------------------------------------------------------------------
      # Optional Binary Ninja support.
      # -------------------------------------------------------------------

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

      makePrintInputsTool =
        pkgs:
        pkgs.writers.writePython3Bin "print-inputs-recursive" { } ''
          import json
          import subprocess

          obj = json.loads(
              subprocess.check_output(["nix", "flake", "archive", "--json"])
          )


          def print_node(node):
              path = node.get("path")
              if path:
                  print(path)
              for _, input_node in (node.get("inputs") or {}).items():
                  print_node(input_node)


          print_node(obj)
        '';

      # -------------------------------------------------------------------
      # User-facing outputs.
      # -------------------------------------------------------------------

      mkDeveloperShell =
        system:
        let
          pkgs = pkgsFor system;
          binaryNinja = binaryNinjaFor system;
          virtualenv = mkLockedVirtualenv system "smallworld-re-dev-env" devSelection;
        in
        pkgs.mkShell {
          packages =
            [
              virtualenv
              # The shellHook below uses `git rev-parse` to find the repo root.
              pkgs.git
              pkgs.uv
              pkgs.nixfmt
              pkgs.nixfmt-tree
            ]
            ++ runtimeToolsFor system
            ++ lib.optional (binaryNinja != null) binaryNinja;

          env = {
            GHIDRA_INSTALL_DIR = ghidraInstallDir pkgs.ghidra;
          };

          hardeningDisable = [ "all" ];

          shellHook = ''
            unset PYTHONPATH
            export REPO_ROOT=$(git rev-parse --show-toplevel)
          ''
          + lib.optionalString (binaryNinja != null) ''
            export BINJA_PATH=${binaryNinja}
            export PYTHONPATH=${binaryNinja}/opt/binaryninja/python:$PYTHONPATH
          '';
        };

      mkPackageOutputs =
        system:
        let
          pkgs = pkgsFor system;
          pythonSet = pythonSets.${system};
          binaryNinja = binaryNinjaFor system;

          virtualenv = mkLockedVirtualenv system "smallworld-re-env" runtimeSelection;
          smallworldEnv = mkDownstreamEnv {
            inherit system;
            name = "smallworld-re-env";
          };
        in
        {
          # `nix build` with no target builds the full runtime environment.
          default = smallworldEnv;
          inherit smallworldEnv;

          # Build just the Python package artifact with:
          #   nix build .#smallworld-re
          "smallworld-re" = pythonSet.smallworld-re;

          # Keep a direct "just the virtualenv" target for convenience.
          venv = virtualenv;

          printInputsRecursive = makePrintInputsTool pkgs;

          dockerImage =
            let
              hasBinaryNinja = binaryNinja != null;
            in
            pkgs.dockerTools.buildImage {
              name = "smallworld-re";
              tag = "latest";

              copyToRoot = pkgs.buildEnv {
                name = "smallworld-root";
                paths =
                  [
                    pkgs.dockerTools.usrBinEnv
                    pkgs.dockerTools.binSh
                    pkgs.dockerTools.caCertificates
                    pkgs.dockerTools.fakeNss
                    pkgs.coreutils
                    pkgs.unzip
                    pkgs.dbus.lib
                    pkgs.stdenv.cc.cc.lib
                    virtualenv
                  ]
                  ++ runtimeToolsFor system
                  ++ lib.optional hasBinaryNinja binaryNinja;

                pathsToLink =
                  [
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
      devShells = forEachSystem (
        system:
        let
          defaultShell = mkDeveloperShell system;
        in
        {
          default = defaultShell;
          # Kept so old shebangs like `nix develop .#pythonEnv` still work.
          pythonEnv = defaultShell;
        }
      );

      packages = forEachSystem mkPackageOutputs;

      # Small helper library for downstream flakes.
      lib = {
        mkEnv = mkDownstreamEnv;
        mkShell = mkDownstreamShell;
        mkPython = mkDownstreamPython;
        mkPythonShell = mkDownstreamPythonShell;
      };

      formatter = forEachSystem (system: (pkgsFor system).nixfmt);
    };
}
