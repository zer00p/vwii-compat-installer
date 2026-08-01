# vWii Compat Installer Rules

These rules dictate how agents should interact with the vWii Compat Installer project.

## Building the App
- The application is built using `make`. It relies on the devkitPPC, devkitARM, and `wut` toolchains, as well as the `libmocha` library.
- To build the release artifacts, run `make release`. The output will be available as `compat_installer-HBL.zip` and `compat_installer-Aroma.zip`.
- You can also build it using the provided `Dockerfile` which defines the necessary build environment.

## Licenses and Crediting
- If we pull code in or use external documentation, we must credit it in the `README.md` and ensure that we strictly obey the original `LICENSE`.
- **Credits Maintenance**: Whenever a new library, tool, or external code is added to the project, both the in-app credits screen (`WUPI_showCredits()` in `src/main.cpp`) and the Credits section in `README.md` must be updated to include proper attribution.

## Learning from the User
- If the user has to explicitly explain a project-specific concept, rule, or workflow to you, you should proactively append that information to this `AGENTS.md` file so that future agents are aware of it.

## Wii U Filesystem (FSA) Rules
- **Memory Alignment**: FSA operations (like `FSAWriteFile` or `FSAReadFile`) strictly require data buffers to be 64-byte aligned (`0x40`). Always use `memalign(0x40, size)` instead of `malloc(size)` for any buffer that will be passed into FSA functions. Failing to do this can result in silent failures or 0-byte files, particularly when memory becomes fragmented during batch operations.
- **Error Checking**: Never ignore the return value of FSA operations. For example, `FSAWriteFile` returns the number of elements written or a negative error code. Always explicitly check that the return value matches the expected write size, and correctly handle the failure by propagating the error or aborting the operation.

## Workspace Clutter and Temporary Files
- Any test scripts, investigation scripts, or temporary data generated during problem-solving should be placed inside `testdata/scripts/` or `testdata/tmp/` to avoid cluttering the project root.
- The `testdata/` folder is ignored in `.gitignore`, ensuring that ephemeral exploration files do not get committed. Do not leave scripts in the root directory.
