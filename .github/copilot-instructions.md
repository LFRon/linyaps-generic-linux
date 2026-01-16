# Copilot instructions (linyaps)

## Big picture
- C++17 monorepo built with CMake; top-level orchestrates libraries in `libs/` and executables in `apps/` via `pfl_add_libraries(...)` (see `CMakeLists.txt`).
- Core implementation lives in `libs/linglong/src/linglong/` (builder/cli/package_manager/repo/runtime). Most apps (`apps/ll-cli`, `apps/ll-builder`, etc.) are thin `main.cpp` entrypoints linking `linglong::linglong`.
- Cross-component APIs:
  - **DBus** contract XML in `api/dbus/*.xml` → C++ interfaces generated at build time in `libs/dbus-api` (see `libs/dbus-api/CMakeLists.txt`). Service-side adaptors are generated in `libs/linglong` (see `libs/linglong/CMakeLists.txt`).
  - **HTTP client** is generated into `external/http` from `api/http/client_swagger.json` (see `tools/run-openapi-generator-cli.sh`).
  - **Typed config/schema** is generated into `libs/api/src/linglong/api/types/v1/` from `api/schema/v1.yaml` (see `tools/codegen.sh`).

## Build / test (preferred)
- Use CMake presets (see `CMakePresets.json`):
  - Debug dev loop: `cmake --workflow --preset debug`
  - Release install: `cmake --workflow --preset release && sudo cmake --install build-release`
  - Run tests only: `ctest --preset debug` (or build target `test` in Ninja builds)
- CI uses Ninja + `-DCPM_LOCAL_PACKAGES_ONLY=ON` by default (see `.github/workflows/build.yaml`). When reproducing CI locally, mirror this flag.

## Lint / formatting
- Repo uses `pre-commit` (see `.pre-commit-config.yaml`):
  - C/C++ formatting: `clang-format --style=file` (hook runs `-i` + `--sort-includes`).
  - Shell formatting: `shfmt -i 4 -ci -sr`.
  - Large generated/vendor trees are excluded (notably `external/`, `docs/`, `po/`, and generated `libs/api/src/linglong/api/types/v1/`).

## Code generation (don’t hand-edit generated outputs)
- C++ schema types:
  - Source of truth: `api/schema/v1.yaml`
  - Regenerate: `./tools/codegen.sh`
  - Output: `libs/api/src/linglong/api/types/v1/*.hpp` (script also rebuilds `api/schema/v1.json`).
- HTTP client:
  - Source of truth: `api/http/client_swagger.json`
  - Regenerate: `./tools/run-openapi-generator-cli.sh`
  - Output: `external/http/` (the script deletes and recreates the directory).

## Coverage / smoke
- Coverage script (runs test binary directly): `./tools/generate-coverage.sh` → report in `build-generate-coverage/report/`.
- End-to-end CLI smoke (requires repos/network): `./tools/test-linglong.sh`.

## Project-specific patterns to follow
- Build system: prefer existing PFL macros (`pfl_add_library`, `pfl_add_executable`) and keep new sources listed explicitly in the corresponding `CMakeLists.txt`.
- Qt5/Qt6 dual support: codepaths often branch on `QT_VERSION_MAJOR`; follow existing patterns in `libs/dbus-api/CMakeLists.txt` and `libs/linglong/CMakeLists.txt` when adding DBus-related code.
- i18n: gettext domain is `linyaps`; translations live in `po/` and are updated via build targets (`make pot`, `make po`) in the build directory (see `DEVELOPER_GUIDE.md`).
