# Provider source notes

Last manually reviewed: 2026-09-02. Only official project pages, infrastructure and
APIs are admitted. Current version numbers and checksums are intentionally not frozen
in manifests; drivers resolve them at runtime and verify the selected artifact.

| Provider | Discovery source | Verification | Important policy |
| --- | --- | --- | --- |
| AlmaLinux OS | official package repository | official SHA-256 CHECKSUM | major version, image type and architecture remain distinct |
| Alpine Linux | `alpinelinux.org/downloads` and official CDN | official SHA-256 sidecar | standard/extended/virtual/Xen and architecture remain distinct |
| Arch Linux | `archlinux.org/download` and the official pkgbuild mirror | SHA-256 + pinned Arch ISO signing key | x86_64 stable only |
| Ubuntu | `releases.ubuntu.com` | official SHA256SUMS | Desktop/server and LTS/interim remain distinct |
| Debian | `cdimage.debian.org` | official SHA512SUMS | netinst, DVD and live variants remain distinct |
| Fedora | Fedora releases metadata and download infrastructure | official SHA-256 CHECKSUM | Workstation, Server, KDE, Silverblue and official desktop Spins remain distinct |
| FreeBSD | official `releases/ISO-IMAGES` index | official SHA-256 list | disc1/DVD/boot-only and architecture remain distinct |
| Gentoo Linux | official autobuild directories on `distfiles.gentoo.org` | official SHA-256 sidecar | minimal/livegui and architecture remain distinct |
| GhostBSD | official project download page and release host | official SHA-256 sidecar | official MATE, community XFCE and Gershwin preview remain distinct |
| Grml | `grml.org/download` and direct official `ftp-master.grml.org` files | official SHA-256 sidecar | full/small and amd64/arm64 remain distinct; rotating mirror redirects are bypassed |
| Haiku | official stable release page and Haiku CDN | SHA-256 embedded in the official page | x86_64 and hybrid x86 GCC2 anyboot images remain distinct |
| Hiren's BootCD PE | official download page | SHA-256 embedded in the official page | stable filename requires explicit replacement |
| Linux Mint | `linuxmint.com/download.php` | official SHA-256 list | Cinnamon, MATE and Xfce remain distinct |
| EndeavourOS | `endeavouros.com` | official SHA-512 sidecar | `.sig` is not trusted until a stable full fingerprint is officially published |
| CachyOS | official wiki and mirror index | SHA-256 + pinned full fingerprint | Desktop and handheld remain distinct |
| Clonezilla Live | `clonezilla.org/downloads` | signed checksum list with pinned DRBL fingerprint | Debian- and Ubuntu-based stable images remain distinct |
| GParted Live | `gparted.org/gparted-live/stable` | signed checksum list with pinned fingerprint | stable amd64 image only |
| Kali Linux | `archive.kali.org/kali-images/current` | signed SHA-256 list with pinned Kali archive fingerprint | quarterly installer/live variants remain distinct |
| KDE neon | official KDE image index and an advertised fixed HTTPS mirror | official SHA-256 sidecar | User, Testing and Unstable channels remain distinct |
| NixOS | `nixos.org/download` and `channels.nixos.org` | official SHA-256 sidecar | graphical/minimal and architecture remain distinct |
| Omarchy | `omarchy.org` and `iso.omarchy.org` | official SHA-256 sidecar | `.sig` is not trusted until a stable full fingerprint is officially published |
| openSUSE Tumbleweed | official openSUSE download service | official SHA-256 sidecar | DVD/net/rescue/live desktop and architecture remain distinct |
| Manjaro | official `manjaro-get-iso` project and download host | official SHA-256 sidecar | preview channel needs persisted manual mapping |
| Memtest86+ | `memtest.org` | SHA-256 list for ZIP archives | detection-only until safe archive extraction exists |
| netboot.xyz | official GitHub releases | GitHub-bound SHA-256 asset digest | standard/legacy and architecture remain distinct |
| NetBSD | official release directory on `cdn.netbsd.org` | official SHA-512 list | amd64/i386 release installers remain distinct |
| Pop!_OS | `system76.com/download-pop` | SHA-256 embedded in the official page | generic/NVIDIA and amd64/arm64 remain distinct |
| PorteuX | official `porteux/porteux` GitHub releases | GitHub-bound SHA-256 asset digest | current desktop and historical stable channels remain distinct; stable is detection-only |
| Proxmox installers | `enterprise.proxmox.com/iso` | signed SHA-256 list with pinned release fingerprint | product and amd64/arm64 remain distinct |
| Qubes OS | official downloads page and security pack | detached OpenPGP signature | detection-only until its signing-key chain is distributed as trusted targets |
| Rescuezilla | official GitHub releases | GitHub-bound SHA-256 asset digest | Ubuntu base variant remains distinct |
| Rocky Linux | official download repository | official SHA-256 CHECKSUM | major version, image type and architecture remain distinct |
| ShredOS | official GitHub releases | GitHub-bound SHA-256 asset digest | architecture, lite/full and partition variants remain distinct |
| Solus | official project download page and release host | official SHA-256 sidecar | Budgie, GNOME, Plasma and Xfce remain distinct |
| Nobara | `nobaraproject.org/download.html` | official SHA-256 sidecar | Official/GNOME/KDE/Steam variants remain distinct |
| SystemRescue | `system-rescue.org/Download` | official SHA-256 sidecar | stable amd64 image only |
| Tails | official stable release JSON and its advertised HTTPS mirrors | embedded SHA-256 | redirects are accepted only to the curated mirror host list |
| TrueNAS Community Edition | official Community Edition page and release hosts | official SHA-256 sidecar | stable and beta channels remain distinct; enterprise media is excluded |
| Vanilla OS | official `Vanilla-OS/live-iso` GitHub releases | SHA-256 release asset | stable assets only |
| Windows 11 | `microsoft.com/software-download/windows11` | SHA-256 from Microsoft's language table | detection and user-supplied official links only |
| Zorin OS | official download and help pages | SHA-256 from official integrity table | Core/Education/Lite only; Pro is detection-only |

## Key decisions

- Arch ISO signer: `3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C`.
- CachyOS signer: `882DCFE48E2051D48E2562ABF3B607488DB35A47`.
- Fedora and Ubuntu publish signed checksum material, but release/key rotation needs a
  dedicated key-set policy. They therefore remain at `CHECKSUM` until that policy is
  represented without silently trusting newly downloaded keys.
- Zorin's free downloads provide official skip/redirect paths. Newsletter submission
  is neither required nor automated.
