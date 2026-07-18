# vWii Compat Installer Rules

These rules dictate how agents should interact with the vWii Compat Installer project.

## Building the App
- The application is built using `make`. It relies on the devkitPPC, devkitARM, and `wut` toolchains, as well as the `libmocha` library.
- To build the release artifacts, run `make release`. The output will be available as `compat_installer-HBL.zip` and `compat_installer-Aroma.zip`.
- You can also build it using the provided `Dockerfile` which defines the necessary build environment.

## Licenses and Crediting
- If we pull code in or use external documentation, we must credit it in the `README.md` and ensure that we strictly obey the original `LICENSE`.

## Learning from the User
- If the user has to explicitly explain a project-specific concept, rule, or workflow to you, you should proactively append that information to this `AGENTS.md` file so that future agents are aware of it.
