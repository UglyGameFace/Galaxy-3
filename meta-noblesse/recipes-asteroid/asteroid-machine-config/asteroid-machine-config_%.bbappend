# R08-only build efficiency: upstream asteroid-machine-config's do_install()
# uses Python's ConfigParser to create etc/asteroid/machine.conf.
# It compiles or links no target code, so requiring cross-gcc and glibc would
# build a full toolchain needlessly on each free ephemeral GitHub runner.
# OE-Core base.bbclass honors INHIBIT_DEFAULT_DEPS before adding BASE_DEFAULT_DEPS.
# Preserve the upstream machine-specific package architecture and contents.
INHIBIT_DEFAULT_DEPS:noblesse-r08 = "1"
