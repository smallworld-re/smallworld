{ pkgs
, stdenv
, zephyr  # from zephyr-nix
, cmake
, ninja
, west2nix
, gitMinimal
}:

let
  west2nixHook = west2nix.mkWest2nixHook {
    manifest = ./west2nix.toml;
  };
in
stdenv.mkDerivation {
  name = "rtos-demo-elf";

  nativeBuildInputs = [
    (zephyr.sdk.override {
      targets = [
        "arm-zephyr-eabi"
      ];
    })
    west2nixHook
    zephyr.pythonEnv
    zephyr.hosttools-nix
    gitMinimal
    cmake
    ninja
    pkgs.python3Packages.jsonschema
  ];

  dontUseCmakeConfigure = true;

  src = pkgs.fetchgit {
    name = "zephyr";
    url = "https://github.com/zephyrproject-rtos/zephyr";
    rev = "e7ae93b39fcb04661e0b03d6c9b86ebc968403d9";
    hash = "sha256-eCAPKPalYa0cW1HC1xRw1CzSdqmazMLLTzjbhHq/TYI=";
  };

  patches = [
    ./udp.c.patch
  ];

  westBuildFlags = [
    "-b"
    "qemu_cortex_a9"
    "samples/net/sockets/echo_server"
  ];

  installPhase = ''
    mkdir $out
    cp ./build/zephyr/zephyr.elf $out/
  '';
}