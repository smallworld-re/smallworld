{
  pkgs,
  stdenv,
  zephyr, # from zephyr-nix
  cmake,
  ninja,
  west2nix,
  gitMinimal,
}:

let
  west2nixHook = west2nix.mkWest2nixHook {
    manifest = ./west2nix.toml;
  };
in
stdenv.mkDerivation {
  name = "rtos-demo-elf";

  nativeBuildInputs = [
    (zephyr.sdk-0_17.override {
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
  ];

  dontUseCmakeConfigure = true;

  src = pkgs.fetchgit {
    name = "zephyr";
    url = "https://github.com/zephyrproject-rtos/zephyr";
    rev = "79e6e32f7904a38cd28c53c0fbbda94c4c05b2f7";
    hash = "sha256-wNG5DsPh0XbunZd7PahGvPahUAVRtVovkEQt02AvXdE=";
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
