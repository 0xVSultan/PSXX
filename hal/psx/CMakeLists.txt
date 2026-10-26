# Build: . ..\..\env.ps1 ; cmake -S hal/psx -B build/psx -G Ninja --toolchain "$env:PSN00BSDK_LIBS/cmake/sdk.cmake" ; cmake --build build/psx
# Emulator test build of the wallet app: add -DPSXX_EMULATED=ON (timing is then not credited).
cmake_minimum_required(VERSION 3.21)
project(psxx LANGUAGES C CXX ASM)

option(PSXX_EMULATED "Wallet app: do not credit timing events (emulator runs)" OFF)

set(CORE ${CMAKE_CURRENT_LIST_DIR}/../../core)
set(CORE_SRC
    ${CORE}/hash/sha256.c ${CORE}/hash/sha2_k.c ${CORE}/hash/sha512.c ${CORE}/hash/sha512_fast.c ${CORE}/hash/keccak.c ${CORE}/hash/keccak_fast.c ${CORE}/hash/ripemd160.c ${CORE}/hash/crc32.c
    ${CORE}/coin/base58.c ${CORE}/coin/bech32.c ${CORE}/coin/keyparse.c ${CORE}/coin/xmr.c ${CORE}/coin/bip32.c ${CORE}/coin/xpub.c ${CORE}/coin/addr.c ${CORE}/coin/bip39.c ${CORE}/coin/words.c ${CORE}/wordlist/wl.c ${CORE}/lang/lang.c ${CORE}/coin/wallet.c ${CORE}/coin/xmr_seed.c
    ${CORE}/entropy.c ${CORE}/qr.c ${CORE}/aes.c ${CORE}/blob.c ${CORE}/b64.c ${CORE}/ur.c ${CORE}/coin/path.c ${CORE}/coin/chains.c ${CORE}/coin/cardano.c ${CORE}/coin/substrate.c ${CORE}/coin/ton.c ${CORE}/coin/orchard.c ${CORE}/coin/orchard_sign.c ${CORE}/ec/pallas.c ${CORE}/hash/blake2b.c ${CORE}/hash/blake3.c ${CORE}/coin/mweb.c ${CORE}/hash/merlin.c
    ${CORE}/ec/bn_comba.c ${CORE}/ec/bn.c ${CORE}/ec/secp_van.c ${CORE}/ec/secp_pub.c ${CORE}/sign/mswallet.c ${CORE}/vanity/vanity.c ${CORE}/ec/fbtab.c ${CORE}/util.c ${CORE}/ec/secp256k1.c ${CORE}/ec/secp256k1_sign.c ${CORE}/sign/btc.c ${CORE}/sign/pb.c ${CORE}/sign/txview.c ${CORE}/sign/evm.c ${CORE}/sign/tron.c ${CORE}/sign/xrp.c ${CORE}/sign/cosmos.c ${CORE}/sign/nostr.c ${CORE}/sign/nip19.c ${CORE}/sign/nip44.c ${CORE}/sign/solana.c ${CORE}/sign/stellar.c ${CORE}/sign/near.c ${CORE}/sign/polkadot.c ${CORE}/sign/ton.c ${CORE}/sign/ada.c ${CORE}/sign/zec.c ${CORE}/sign/xmr.c ${CORE}/sign/redpallas.c ${CORE}/sign/orchard_out.c ${CORE}/hash/chacha20poly1305.c ${CORE}/ec/poseidon.c ${CORE}/sign/dispatch.c ${CORE}/sign/kaspa.c ${CORE}/sign/btcmsg.c ${CORE}/ec/ed25519.c ${CORE}/ec/ed25519_sign.c)
set(HAL_SRC gpu.c timer.c pad.c input.c qr_view.c font.c keyboard.c coin.c dice.c cdrom.c mcard.c cdlog.c cdview.c mcfile.c keystore.c)

# The texts of the screens: tools/strings/{en,hu}_<range>.txt -> the identifiers (ui_ids.h) and the tables of the three ranges (a: the main card, b: the signer,
# l: the language module). UI_A is the code that looks a text up and the tables of the main card; a program that shows converted screens needs it, the signer UI_B and the module UI_L.
set(TOOLS ${CMAKE_CURRENT_LIST_DIR}/../../tools)
find_program(PSXX_PYTHON NAMES python3 python py NO_CMAKE_FIND_ROOT_PATH REQUIRED)
set(UIGEN ${CMAKE_CURRENT_BINARY_DIR}/gen)
file(GLOB UI_LISTS CONFIGURE_DEPENDS ${TOOLS}/strings/*_?.txt)
add_custom_command(OUTPUT ${UIGEN}/ui_ids.h ${UIGEN}/ui_tabs_a.c ${UIGEN}/ui_tabs_b.c ${UIGEN}/ui_tabs_l.c
    COMMAND ${PSXX_PYTHON} ${TOOLS}/ui_ids.py gen --out ${UIGEN}
    DEPENDS ${UI_LISTS} ${TOOLS}/ui_ids.py ${TOOLS}/ui_strings.py)
add_custom_target(psxx_ui_gen DEPENDS ${UIGEN}/ui_ids.h ${UIGEN}/ui_tabs_a.c ${UIGEN}/ui_tabs_b.c ${UIGEN}/ui_tabs_l.c)
set(UI_A ui_text.c ${UIGEN}/ui_tabs_a.c)
set(UI_B ${UIGEN}/ui_tabs_b.c)
set(UI_L ${UIGEN}/ui_tabs_l.c)
function(psxx_ui target)                  # the generated header (ui_ids.h) for a target whose sources use the identifiers
    target_include_directories(${target} PRIVATE ${UIGEN} ${CMAKE_CURRENT_LIST_DIR})
    add_dependencies(${target} psxx_ui_gen)
endfunction()
set_source_files_properties(ui_text.c ${UIGEN}/ui_tabs_a.c ${UIGEN}/ui_tabs_b.c ${UIGEN}/ui_tabs_l.c PROPERTIES COMPILE_OPTIONS -Os)

# Hello world (boot card check)
psn00bsdk_add_executable(psxx GPREL main.c gpu.c font.c)

# Memory layout test for card boots: hello world + large BSS (see bss_test.c)
psn00bsdk_add_executable(psxx_bsstest GPREL bss_test.c gpu.c font.c)
target_compile_definitions(psxx_bsstest PRIVATE BSS_KB=72)

# On-screen keyboard test (accent mode)
psn00bsdk_add_executable(psxx_kbtest GPREL kbtest.c gpu.c font.c timer.c pad.c input.c keyboard.c ${CORE}/entropy.c ${CORE}/hash/sha256.c ${CORE}/hash/sha2_k.c ${CORE}/util.c ${UI_A})
target_include_directories(psxx_kbtest PRIVATE ${CORE})
psxx_ui(psxx_kbtest)

# Test of the hide-wallet mode (hide.h): a CD player disguise with a gesture and a session PIN; needs a disc with audio tracks (tools/gen_testdisc.py)
psn00bsdk_add_executable(psxx_hidetest GPREL hidetest.c hide.c gpu.c font.c timer.c pad.c input.c cdrom.c ${CORE}/entropy.c ${CORE}/hash/sha256.c ${CORE}/hash/sha2_k.c ${CORE}/util.c)
target_include_directories(psxx_hidetest PRIVATE ${CORE})
psxx_ui(psxx_hidetest)

# M0: memory card slot probe (presence, card change, polling cost; TTY and screen), linked high like the apps
psn00bsdk_add_executable(psxx_cardprobe GPREL cardprobe.c gpu.c font.c timer.c pad.c input.c mcard.c ${CORE}/entropy.c ${CORE}/hash/sha256.c ${CORE}/hash/sha2_k.c ${CORE}/util.c ${CORE}/hash/crc32.c)
target_include_directories(psxx_cardprobe PRIVATE ${CORE})
get_target_property(_cp psxx_cardprobe LINK_OPTIONS)
list(FILTER _cp EXCLUDE REGEX "exe\.ld")
set_target_properties(psxx_cardprobe PROPERTIES LINK_OPTIONS "${_cp};-T${CMAKE_CURRENT_LIST_DIR}/exe_hi.ld")

# The memory probe: which main RAM does the BIOS write while a program of ours runs; linked high like the apps, the report goes to the TTY, the screen and a card file
psn00bsdk_add_executable(psxx_memprobe GPREL memprobe.c gpu.c font.c timer.c pad.c input.c mcard.c mcfile.c cdrom.c ${CORE}/entropy.c ${CORE}/hash/sha256.c ${CORE}/hash/sha2_k.c ${CORE}/util.c ${CORE}/hash/crc32.c)
target_include_directories(psxx_memprobe PRIVATE ${CORE})
get_target_property(_mpb psxx_memprobe LINK_OPTIONS)
list(FILTER _mpb EXCLUDE REGEX "exe\.ld")
set_target_properties(psxx_memprobe PROPERTIES LINK_OPTIONS "${_mpb};-T${CMAKE_CURRENT_LIST_DIR}/exe_hi.ld")

# K5a: what the SPU RAM, the VRAM and the main RAM give to Argon2id (speed, correctness; the TTY has the [mp] lines), linked high like the apps
psn00bsdk_add_executable(psxx_mempool_probe GPREL mempool_probe.c mempool.c gpu.c font.c timer.c pad.c input.c ${CORE}/entropy.c ${CORE}/hash/sha256.c ${CORE}/hash/sha2_k.c ${CORE}/util.c ${CORE}/hash/blake2b.c ${CORE}/hash/argon2.c)
target_include_directories(psxx_mempool_probe PRIVATE ${CORE})
get_target_property(_mp psxx_mempool_probe LINK_OPTIONS)
list(FILTER _mp EXCLUDE REGEX "exe\.ld")
set_target_properties(psxx_mempool_probe PROPERTIES LINK_OPTIONS "${_mp};-T${CMAKE_CURRENT_LIST_DIR}/exe_hi.ld")

# Timing/size probe of the crypto core (output on the TTY)
psn00bsdk_add_executable(psxx_bench GPREL bench.c ${CORE_SRC} ${UI_A} ${UI_B})
target_include_directories(psxx_bench PRIVATE ${CORE})
psxx_ui(psxx_bench)
# How fast the vanity search is (TTY): the secp256k1 source is compiled with the search kernel (vanity_secp.c) instead of core/ec/secp256k1.c
set(VB_SRC ${CORE_SRC})
set(VB_FAST vb_fast_sha.c vb_fast_rmd.c vb_fast_kec.c vb_keccak23.c)
set_source_files_properties(${VB_FAST} PROPERTIES COMPILE_OPTIONS "-O2;-funroll-loops")
# copies of the hashes under the names <name>_... compiled with other options, generated here (see vb_rename.h for the idea)
function(vb_variant name opts)
    set(dir ${CMAKE_CURRENT_BINARY_DIR}/vbgen)
    file(MAKE_DIRECTORY ${dir})
    set(ren "")
    foreach(f sha256_init sha256_update sha256_final sha256_tagged_init sha256 hmac_sha256 ripemd160 hash160 keccak256 keccak_f1600)
        list(APPEND ren "${f}=${name}_${f}")
    endforeach()
    file(WRITE ${dir}/${name}_sha.c "#include \"${CORE}/hash/sha256.c\"
")
    file(WRITE ${dir}/${name}_rmd.c "#include \"${CORE}/hash/ripemd160.c\"
")
    file(WRITE ${dir}/${name}_kec.c "#define KECCAK_SCRATCH 1
#include \"${CORE}/hash/keccak_fast.c\"
#include \"${CORE}/hash/keccak.c\"
")
    file(WRITE ${dir}/${name}_tail.c "#include \"${CMAKE_CURRENT_LIST_DIR}/vb_keccak23g.c\"
")
    set_source_files_properties(${dir}/${name}_sha.c ${dir}/${name}_rmd.c ${dir}/${name}_kec.c PROPERTIES COMPILE_OPTIONS "${opts}" COMPILE_DEFINITIONS "${ren}")
    set_source_files_properties(${dir}/${name}_tail.c PROPERTIES COMPILE_OPTIONS "${opts}" COMPILE_DEFINITIONS "vl_eth_address=${name}_eth_address;vl_f1600_23=${name}_f1600_23")
    set(VB_${name}_SRC ${dir}/${name}_sha.c ${dir}/${name}_rmd.c ${dir}/${name}_kec.c ${dir}/${name}_tail.c PARENT_SCOPE)
endfunction()
vb_variant(vo1 "-O1")
vb_variant(vos "-Os")
set(VB_G vb_g_sha.c vb_g_rmd.c vb_g_kec.c vb_keccak23g.c)
set_source_files_properties(${VB_G} PROPERTIES COMPILE_OPTIONS "-O2;-fno-unroll-loops")
set_source_files_properties(${CORE}/ec/secp_van.c PROPERTIES COMPILE_OPTIONS -Os)
psn00bsdk_add_executable(psxx_vbench GPREL vbench.c timer.c ${VB_FAST} ${VB_G} ${VB_vo1_SRC} ${VB_vos_SRC} ${VB_SRC} ${UI_A} ${UI_B})
target_include_directories(psxx_vbench PRIVATE ${CORE})
psxx_ui(psxx_vbench)
# How long it takes to build the table of the Sinsemilla points (TTY)
psn00bsdk_add_executable(psxx_sinbench GPREL sinbench.c ${CORE_SRC} ${UI_A} ${UI_B})
target_include_directories(psxx_sinbench PRIVATE ${CORE})
psxx_ui(psxx_sinbench)
psn00bsdk_add_executable(psxx_sinbench2 GPREL sinbench2.c ${CORE_SRC} ${UI_A} ${UI_B})
target_include_directories(psxx_sinbench2 PRIVATE ${CORE})
psxx_ui(psxx_sinbench2)

# Wallet generator: entropy -> BIP39 words -> addresses
psn00bsdk_add_executable(psxx_wallet GPREL wallet_app.c ${HAL_SRC} ${CORE_SRC} ${CORE}/keyfile.c ${CORE}/pwtools.c ${UI_A})   # keyfile.c: the key stores
target_include_directories(psxx_wallet PRIVATE ${CORE})
psxx_ui(psxx_wallet)
# The signer has no executable of its own any more: it is the overlay of the second card (B). Its source files and their -Os stay here, the overlay targets use them.
set(SIGNER_HAL gpu.c timer.c pad.c input.c qr_view.c font.c keyboard.c mcard.c mcfile.c)
set_source_files_properties(signer_app.c ${SIGNER_HAL} PROPERTIES COMPILE_OPTIONS -Os)
set_source_files_properties(keystore.c ${CORE}/keyfile.c PROPERTIES COMPILE_OPTIONS -Os)

# The fixed places of the overlays and their data (memmap.h), and a linker script for each overlay made from ovl.ld.in: the signer (bss in pocket 1), the language module (bss after the image)
file(STRINGS ${CMAKE_CURRENT_LIST_DIR}/memmap.h _mm REGEX "^#define MM_[A-Z0-9_]+ +0x[0-9A-Fa-f]+u")
foreach(_l ${_mm})
    string(REGEX REPLACE "^#define (MM_[A-Z0-9_]+) +(0x[0-9A-Fa-f]+)u.*$" "\\1;\\2" _kv "${_l}")
    list(GET _kv 0 _k)
    list(GET _kv 1 _v)
    set(${_k} ${_v})
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/memmap.h ${CMAKE_CURRENT_LIST_DIR}/ovl.ld.in)
function(psxx_ovl_script out code_lo code_hi bss_lo bss_hi)
    math(EXPR CODE_LEN "${code_hi} - ${code_lo}" OUTPUT_FORMAT HEXADECIMAL)
    set(CODE_LO ${code_lo})
    if(bss_lo)
        math(EXPR _bl "${bss_hi} - ${bss_lo}" OUTPUT_FORMAT HEXADECIMAL)
        set(BSS_MEMORY "\tBSS_RAM (rw) : ORIGIN = ${bss_lo}, LENGTH = ${_bl}")
        set(BSS_REGION BSS_RAM)
    else()
        set(BSS_MEMORY "")
        set(BSS_REGION OVL_RAM)
    endif()
    configure_file(${CMAKE_CURRENT_LIST_DIR}/ovl.ld.in ${out} @ONLY)
endfunction()
set(OVL_LD_SIG ${CMAKE_CURRENT_BINARY_DIR}/ovl_sig.ld)
set(OVL_LD_LANG ${CMAKE_CURRENT_BINARY_DIR}/ovl_lang.ld)
psxx_ovl_script(${OVL_LD_SIG} ${MM_SIG_LO} ${MM_SIG_HI} ${MM_P1_LO} ${MM_P1_HI})
psxx_ovl_script(${OVL_LD_LANG} ${MM_LANG_LO} ${MM_LANG_HI} "" "")

# M2: a base image with a release record, and an overlay linked at a fixed address against it (see ovl.ld.in, tools/release.py)
set(OVL_BASE_VARIANT 0 CACHE STRING "demo base: a number built into the image, to make a different build for the tests of tools/release.py")
psn00bsdk_add_executable(psxx_ovl_base GPREL ovl_base_demo.c release.c loader.c card_watch.c source_ui.c gpu.c font.c timer.c pad.c input.c mcard.c ${CORE}/entropy.c ${CORE}/hash/sha256.c ${CORE}/hash/sha2_k.c
                         ${CORE}/hash/crc32.c ${CORE}/pkg/pkg.c ${CORE}/pkg/cardfile.c ${CORE}/pkg/ovl.c ${CORE}/pkg/watch.c ${CORE}/pkg/dirscan.c ${CORE}/ec/secp256k1.c ${CORE}/ec/fbtab.c ${CORE}/ec/bn.c ${CORE}/ec/bn_comba.c ${CORE}/util.c ${UI_A})   # the loader checks the BIP340 signature of a package
target_include_directories(psxx_ovl_base PRIVATE ${CORE})
psxx_ui(psxx_ovl_base)
target_compile_definitions(psxx_ovl_base PRIVATE BASE_VARIANT=${OVL_BASE_VARIANT})
get_target_property(_ob psxx_ovl_base LINK_OPTIONS)
list(FILTER _ob EXCLUDE REGEX "exe\.ld")
# the functions the overlay calls have to be in the base even if the base does not call them (the export list of the overlay)
set_target_properties(psxx_ovl_base PROPERTIES LINK_OPTIONS "${_ob};-T${CMAKE_CURRENT_LIST_DIR}/exe_hi.ld;-Wl,-u,sha256;-Wl,-u,printf")

set(OVL_BASE_SYMS ${CMAKE_CURRENT_BINARY_DIR}/psxx_ovl_base_syms.ld)
add_custom_command(OUTPUT ${OVL_BASE_SYMS}
    COMMAND ${CMAKE_COMMAND} -DNM=${TOOLCHAIN_NM} -DELF=$<TARGET_FILE:psxx_ovl_base> -DOUT=${OVL_BASE_SYMS} -P ${CMAKE_CURRENT_LIST_DIR}/gen_syms.cmake
    DEPENDS psxx_ovl_base ${CMAKE_CURRENT_LIST_DIR}/gen_syms.cmake)
add_custom_target(psxx_ovl_base_syms DEPENDS ${OVL_BASE_SYMS})

psn00bsdk_add_executable(psxx_ovl_demo NOGPREL ovl_demo.c)
target_include_directories(psxx_ovl_demo PRIVATE ${CORE})
add_dependencies(psxx_ovl_demo psxx_ovl_base_syms)
get_target_property(_od psxx_ovl_demo LINK_OPTIONS)
list(FILTER _od EXCLUDE REGEX "exe\.ld")
set_target_properties(psxx_ovl_demo PROPERTIES LINK_OPTIONS "${_od};-T${OVL_LD_SIG}" LINK_DEPENDS "${OVL_BASE_SYMS};${OVL_LD_SIG}")
target_link_libraries(psxx_ovl_demo PRIVATE ${OVL_BASE_SYMS})                  # the addresses of the base, as an input linker script

# Card boot: the BIOS shell stays in RAM at 0x80030000..0x800A6000, so the program is linked at 0x80110000 (exe_hi.ld).
get_target_property(_lo psxx_wallet LINK_OPTIONS)
list(FILTER _lo EXCLUDE REGEX "exe\.ld")
set_target_properties(psxx_wallet PROPERTIES LINK_OPTIONS "${_lo};-T${CMAKE_CURRENT_LIST_DIR}/exe_hi.ld")
# Optimise for size: the whole payload has to fit what the FreePSXBoot loader can bring up from a memory card.
# (-O2 is added by the SDK after any target option, so use per-source options, which come last.)
# Hot crypto files can be switched back to -O2 individually once speed matters (M3).
set_source_files_properties(wallet_app.c ${HAL_SRC} ${CORE_SRC} ${CORE}/keyfile.c ${CORE}/pwtools.c keccak_ram.c PROPERTIES COMPILE_OPTIONS -Os)
# Keccak: the state lives in the scratchpad (1 cycle loads; main RAM costs ~6), see core/hash/keccak_fast.c
set_source_files_properties(${CORE}/hash/keccak_fast.c PROPERTIES COMPILE_DEFINITIONS KECCAK_SCRATCH)
# SHA-512: the 640 byte message schedule lives in the scratchpad too (Keccak and SHA-512 never run at the same time)
set_source_files_properties(${CORE}/hash/sha512_fast.c PROPERTIES COMPILE_DEFINITIONS "SHA512_SCRATCH;SHA512_X8")
# Pallas (Zcash Orchard): the 17 word product of every field multiplication lives in the scratchpad at 0x1F800380
set_source_files_properties(${CORE}/ec/pallas.c PROPERTIES COMPILE_DEFINITIONS PALLAS_SCRATCH)
if(PSXX_EMULATED)
    target_compile_definitions(psxx_wallet PRIVATE PSXX_EMULATED=1)
endif()

# 256 bit multiplication: CPU alone against CPU + GTE (see the comment at the top of bench_gte.c); runs as a plain exe
psn00bsdk_add_executable(psxx_bench_gte GPREL bench_gte.c gpu.c font.c timer.c pad.c input.c ${CORE}/entropy.c ${CORE}/hash/sha256.c ${CORE}/hash/sha2_k.c ${CORE}/util.c ${CORE}/hash/keccak.c ${CORE}/hash/keccak_fast.c keccak_ram.c ${CORE}/hash/sha512_fast.c ${CORE}/ec/bn_comba.c)
target_include_directories(psxx_bench_gte PRIVATE ${CORE})

# ---- M4: A = the generator with the loader (the base), B = the signer (the overlay) ----
# The files only the signer needs are the overlay; everything else, the hash and curve code the generator uses too and the whole HAL, stays in the base and is called from the overlay at
# its address in the base (gen_syms.cmake). What the overlay calls, the base keeps in the link (gen_exports.cmake).
set(OVL_ONLY_SRC
    ${CORE}/sign/btc.c ${CORE}/sign/pb.c ${CORE}/sign/txview.c ${CORE}/sign/evm.c ${CORE}/sign/tron.c ${CORE}/sign/xrp.c ${CORE}/sign/cosmos.c ${CORE}/sign/nostr.c ${CORE}/sign/nip19.c ${CORE}/sign/nip44.c ${CORE}/sign/solana.c ${CORE}/sign/stellar.c
    ${CORE}/sign/near.c ${CORE}/sign/polkadot.c ${CORE}/sign/ton.c ${CORE}/sign/ada.c ${CORE}/sign/zec.c ${CORE}/sign/xmr.c ${CORE}/sign/redpallas.c ${CORE}/sign/orchard_out.c
    ${CORE}/ec/secp_van.c ${CORE}/ec/secp_pub.c ${CORE}/sign/mswallet.c ${CORE}/vanity/vanity.c ${CORE}/sign/dispatch.c ${CORE}/sign/kaspa.c ${CORE}/sign/btcmsg.c ${CORE}/ec/ed25519_sign.c ${CORE}/ec/secp256k1_sign.c ${CORE}/hash/chacha20poly1305.c ${CORE}/ec/poseidon.c ${CORE}/coin/orchard_sign.c ${CORE}/coin/keyparse.c)
set(BASE_CORE_SRC ${CORE_SRC})
set(LANG_SRC lang_ui.c fontext.c ${CORE}/lang/lang.c ${CORE}/lang/nfkd.c ${CORE}/lang/langin.c)                  # the language module: the second overlay, in the package of B (group 2)
list(REMOVE_ITEM BASE_CORE_SRC ${OVL_ONLY_SRC} ${CORE}/lang/lang.c)
set(LOADER_SRC release.c loader.c card_watch.c source_ui.c ${CORE}/pkg/pkg.c ${CORE}/pkg/cardfile.c ${CORE}/pkg/ovl.c ${CORE}/pkg/watch.c ${CORE}/pkg/dirscan.c)
set_source_files_properties(${LOADER_SRC} ${LANG_SRC} divdi3.c vsnprintf.c PROPERTIES COMPILE_OPTIONS -Os)

# B: the objects first (the export list comes from them), then the link against the base
add_library(psxx_b_obj OBJECT signer_app.c keystore_del.c ${CORE}/keyfile_open.c ${OVL_ONLY_SRC} ${UI_B})
set_target_properties(psxx_b_obj PROPERTIES PSN00BSDK_TARGET_TYPE EXECUTABLE_NOGPREL)
target_link_libraries(psxx_b_obj PRIVATE ${PSN00BSDK_EXECUTABLE_LINK_LIBRARIES})
target_include_directories(psxx_b_obj PRIVATE ${CORE})
psxx_ui(psxx_b_obj)
target_compile_definitions(psxx_b_obj PRIVATE PSX_PROF=1 SIGNER_KEYS=1 SIGNER_OVERLAY=1)
if(PSXX_EMULATED)
    target_compile_definitions(psxx_b_obj PRIVATE PSXX_EMULATED=1)
endif()
# L: the language module, the same way
add_library(psxx_l_obj OBJECT ${LANG_SRC} ${UI_L})
set_target_properties(psxx_l_obj PROPERTIES PSN00BSDK_TARGET_TYPE EXECUTABLE_NOGPREL)
target_link_libraries(psxx_l_obj PRIVATE ${PSN00BSDK_EXECUTABLE_LINK_LIBRARIES})
target_include_directories(psxx_l_obj PRIVATE ${CORE})
psxx_ui(psxx_l_obj)
set(B_EXPORTS ${CMAKE_CURRENT_BINARY_DIR}/psxx_b_exports.ld)
set(B_EXPORTS_RSP ${CMAKE_CURRENT_BINARY_DIR}/psxx_b_exports.rsp)
add_custom_command(OUTPUT ${B_EXPORTS} ${B_EXPORTS_RSP}
    COMMAND ${CMAKE_COMMAND} -DNM=${TOOLCHAIN_NM} -DREADELF=${CMAKE_READELF} "-DOBJS=$<JOIN:$<TARGET_OBJECTS:psxx_b_obj>,@@>@@$<JOIN:$<TARGET_OBJECTS:psxx_l_obj>,@@>" -DOUT=${B_EXPORTS} -DRSP=${B_EXPORTS_RSP} -P ${CMAKE_CURRENT_LIST_DIR}/gen_exports.cmake
    DEPENDS psxx_b_obj psxx_l_obj $<TARGET_OBJECTS:psxx_b_obj> $<TARGET_OBJECTS:psxx_l_obj> ${CMAKE_CURRENT_LIST_DIR}/gen_exports.cmake)   # the objects too: an OBJECT library is no file to depend on

# link-time optimisation of A, B and the language module: the objects are fat (gen_exports.cmake reads their symbols and relocations),
# and the exports of A go to its link as -u options too (an LTO link does not keep what EXTERN names). cmake -DPSXX_LTO=OFF (tools/release.py build --no-lto) leaves it out.
option(PSXX_LTO "link-time optimisation of the main card, the signer and the language module" ON)
if(PSXX_LTO)
    target_compile_options(psxx_b_obj PRIVATE -flto -ffat-lto-objects)
    target_compile_options(psxx_l_obj PRIVATE -flto -ffat-lto-objects)
endif()

# the production build has no TTY diagnostics (log.h): cmake -DPSXX_QUIET=ON (tools/release.py build --quiet)
option(PSXX_QUIET "no TTY diagnostics in the main card, the signer and the language module" OFF)
if(PSXX_QUIET)
    target_compile_definitions(psxx_b_obj PRIVATE PSXX_QUIET=1)
    target_compile_definitions(psxx_l_obj PRIVATE PSXX_QUIET=1)
endif()

# A
psn00bsdk_add_executable(psxx_a GPREL wallet_app.c ${HAL_SRC} ${BASE_CORE_SRC} ${CORE}/keyfile.c ${CORE}/pwtools.c ${LOADER_SRC} divdi3.c vsnprintf.c ${UI_A})   # divdi3.c, vsnprintf.c: the small 64 bit division and formatting instead of libgcc's and the SDK's
target_include_directories(psxx_a PRIVATE ${CORE})
psxx_ui(psxx_a)
target_compile_definitions(psxx_a PRIVATE WITH_LOADER=1 FONT_EXT=1)
if(PSXX_QUIET)
    target_compile_definitions(psxx_a PRIVATE PSXX_QUIET=1)
endif()
if(PSXX_EMULATED)
    target_compile_definitions(psxx_a PRIVATE PSXX_EMULATED=1)
endif()
# a release build has no LZMA decoder in the main card: the unpacking stub of the boot card leaves its own in a pocket (memmap.h MM_DEC_LO, core/pkg/ovl.c). Such an EXE only runs
# packed with tools/packexe.py --ext-dec; the plain build (dev runs of psxx_a.exe) keeps the decoder in the image. tools/release.py build turns it on.
option(PSXX_EXT_DEC "main card: use the decoder that the unpacking stub leaves in its pocket" OFF)
if(PSXX_EXT_DEC)
    target_compile_definitions(psxx_a PRIVATE PSXX_EXT_DEC=1)
endif()
get_target_property(_al psxx_a LINK_OPTIONS)
list(FILTER _al EXCLUDE REGEX "exe\.ld")
set_target_properties(psxx_a PROPERTIES LINK_OPTIONS "${_al};-T${CMAKE_CURRENT_LIST_DIR}/exe_hi.ld" LINK_DEPENDS "${B_EXPORTS};${B_EXPORTS_RSP}")
target_link_libraries(psxx_a PRIVATE ${B_EXPORTS})
if(PSXX_LTO)
    target_compile_options(psxx_a PRIVATE -flto -ffat-lto-objects)
    target_link_options(psxx_a PRIVATE -flto -Os "-Wl,@${B_EXPORTS_RSP}")
endif()
add_custom_target(psxx_b_exports DEPENDS ${B_EXPORTS})
add_dependencies(psxx_a psxx_b_exports)

set(B_SYMS ${CMAKE_CURRENT_BINARY_DIR}/psxx_a_syms.ld)
add_custom_command(OUTPUT ${B_SYMS}
    COMMAND ${CMAKE_COMMAND} -DNM=${TOOLCHAIN_NM} -DELF=$<TARGET_FILE:psxx_a> -DOUT=${B_SYMS} -P ${CMAKE_CURRENT_LIST_DIR}/gen_syms.cmake
    DEPENDS psxx_a ${CMAKE_CURRENT_LIST_DIR}/gen_syms.cmake)
add_custom_target(psxx_a_syms DEPENDS ${B_SYMS})

# B: the overlay (ovl_sig.ld) against the addresses of A
psn00bsdk_add_executable(psxx_b NOGPREL $<TARGET_OBJECTS:psxx_b_obj>)
set_target_properties(psxx_b PROPERTIES LINKER_LANGUAGE C)
add_dependencies(psxx_b psxx_a_syms)
get_target_property(_bl psxx_b LINK_OPTIONS)
list(FILTER _bl EXCLUDE REGEX "exe\.ld")
set_target_properties(psxx_b PROPERTIES LINK_OPTIONS "${_bl};-T${OVL_LD_SIG}" LINK_DEPENDS "${B_SYMS};${OVL_LD_SIG}")
target_link_libraries(psxx_b PRIVATE ${B_SYMS})
if(PSXX_LTO)
    target_link_options(psxx_b PRIVATE -flto -Os)
endif()

# L: the language module (ovl_lang.ld) against the addresses of A, like B
psn00bsdk_add_executable(psxx_l NOGPREL $<TARGET_OBJECTS:psxx_l_obj>)
set_target_properties(psxx_l PROPERTIES LINKER_LANGUAGE C)
add_dependencies(psxx_l psxx_a_syms)
get_target_property(_ll psxx_l LINK_OPTIONS)
list(FILTER _ll EXCLUDE REGEX "exe\.ld")
set_target_properties(psxx_l PROPERTIES LINK_OPTIONS "${_ll};-T${OVL_LD_LANG}" LINK_DEPENDS "${B_SYMS};${OVL_LD_LANG}")
target_link_libraries(psxx_l PRIVATE ${B_SYMS})
if(PSXX_LTO)
    target_link_options(psxx_l PRIVATE -flto -Os)
endif()
