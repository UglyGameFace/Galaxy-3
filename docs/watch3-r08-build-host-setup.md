# Galaxy Watch3 R08: run the off-device graphical filesystem build

## What is actually needed

The real `wl_shm` host Qt compositor round-trip [passed](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39695926149/job/119553160094).
The next unverified gate is the **target AArch64 AsteroidOS root filesystem**.
The [manual build workflow](../.github/workflows/watch3-r08-graphical-rootfs.yml)
runs `bitbake -c rootfs asteroid-image`, then inspects its real
`IMAGE_ROOTFS` directory, `IMAGE_MANIFEST`, and ARM64 Qt binaries.
It does not generate a signed or flashable firmware image or contact the watch.

GitHub's standard `ubuntu-22.04` runner has only **14 GB SSD**, so it
cannot meet this project's 120 GiB free-space safety gate.
A temporary Linux **x86-64** server is required; the workflow no longer offers
the unusable standard runner choice. GitHub larger managed runners are
primarily available on eligible organization/enterprise plans, not a
personal-account repository.

## Safest temporary build machine

Provision a **disposable VM** from a provider you choose, with:

- **OS:** Ubuntu 22.04 LTS x86-64
- **CPU:** 4 or more x86-64 vCPUs; 8 is preferable for a large cold build
- **Memory:** at least 16 GiB RAM
- **SSD:** 200 GiB or more, ensuring **120 GiB free** after the OS and tools
- **Connectivity:** outbound HTTPS to GitHub, upstream Qt/Yocto sources,
  Ubuntu apt mirrors; sufficient bandwidth and time for a cold BitBake build

**Public-repository security caveat:** GitHub advises *against persistent
self-hosted runners for public repos*. A pull request can potentially execute
untrusted code on a registered runner. Use a brand-new isolated VM with no
personal files or credentials, no other workloads, no cloud admin credentials
available to builds, and a narrowly scoped ephemeral GitHub runner that is
removed and the VM destroyed after the single job. Never paste runner
registration tokens into this repository, a GitHub issue, or ChatGPT.
If the VM cannot be isolated this way, **do not register a runner**.
A protected private build repository or trusted standalone cloud build is
safer for repeat builds.

## From Android: GitHub configuration

1. On your phone, open the
   [Galaxy-3 repository](https://github.com/UglyGameFace/Galaxy-3),
   choose **Settings → Actions → Runners → New self-hosted runner**
   (use your browser's desktop-site mode if necessary).
2. Select **Linux** and **x64**. GitHub supplies current download,
   integrity-check and registration commands. Run those commands in the
   cloud VM's browser-accessible console **as a dedicated non-root user**.
   Registration requires a short-lived token which stays on your VM.
3. When running GitHub's generated `./config.sh` registration command,
   append `--ephemeral --labels watch3-yocto`. This makes the runner take
   **one job only** and automatically deregister after it runs, reducing
   exposure on a public repository. The workflow expects all of
   `self-hosted`, `linux`, `x64`, `watch3-yocto`. Start the registered
   runner with `./run.sh` and leave its VM console running while the build
   executes.
4. The workflow installs dependencies via `sudo apt-get`. The runner user
   therefore needs suitable non-interactive sudo permission for apt on this
   throwaway machine. Do not use a personal machine or share its credentials.
   Confirm the runner displays **Idle** in GitHub.
5. Open the
   [Graphical rootfs workflow](https://github.com/UglyGameFace/Galaxy-3/actions/workflows/watch3-r08-graphical-rootfs.yml)
   → **Run workflow** → branch `main` → enter
   `BUILD_OFF_DEVICE_ROOTFS_ONLY` in **confirm** → Run workflow.
   This is an **expensive** cold compilation. It runs only when manually
   dispatched and when the guarded capacity checks pass.
6. Review the job result and its **diagnostics-only** artifact. The final
   `Inspect actual ARM64 rootfs and installed package manifest` step
   must pass. Do not infer hardware compatibility even from a green job.
   Stop the runner and delete the temporary VM after reading results so
   the provider does not keep billing you.

**No bootloader, flash, Tizen partition, or physical Watch3 action belongs
in this procedure.** Custom boot/recovery are unverified for R08. Do not flash.

## What to report for the next decision

The GitHub Actions run URL for the graphical rootfs job is enough to inspect
its output and distinguish a source recipe failure, exhausted disk, bad package
closure, or successful real ARM64 filesystem validation. No screenshots,
tokens, binary firmware or watch access are required.

References:

- [GitHub runner hardware limits](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub adding self-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/add-runners)
- [GitHub security warning for public-repo self-hosted runners](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub one-job ephemeral self-hosted runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
