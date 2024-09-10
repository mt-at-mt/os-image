# Verified Boot Concept

This is a demo for a [verified boot](#verified boot) concept.

## About this PoC

It uses mkosi for image generation and u-boot with EFI support for booting.
It is based on the usage of a TPM2.

And should fulfill the requirements for
[ArmSystemReady IR certification](https://www.arm.com/architecture/system-architectures/systemready-certification-program/ir#certifications).

This also means, that this OS can be used on any board with this certification.

Something similar is implemented by Linaro called
[Trusted Reference Stack](https://trs.readthedocs.io/en/latest)


### Why?

(u)EFI is a common standard for booting devices. If a device provides an EFI
interface booting an image is the same as on a generic x86 platform.

u-boot supports secure-boot with an UEFI interface:
https://linaro.org/blog/enabling-uefi-secure-boot-on-u-boot/

mkosi supports dm-crypt, dm-verity and verified boot. It is able to generate
images from different distributions and for different runtime environments
(systemd-nspawn containers, native images, qemu, ..). It does not require root
privileges for building images.
It implements the specifications defined by the uapi-group:
https://uapi-group.org/specifications


## TPM2 (Trusted Platform Module)

A TPM implements a clearly defined set of functionalities:

- Random Number Generator (RNG)
- Keygenerator
- Hashgenerator
- Crypt and Decrypt Engine
- Signing Engine
- Attestation Identity Keys (AIK)
- Platform Configuration Regsiters (PCR) signed by AIK
- Storage Root Key (SRK)
- Key storage signed by SRK

Use-cases:

- Sealing (Sign data with TPM instance specific key) / can only be decrypted on same machine
- Encrypt/Decrypt data or additional keys on mass-storage
- Remote attestation

The communication with a TPM implementation follows an open standard.

There is a TSS spec (and Linux implementation) for a software API.

TSS is available as backend for e.g. openssl or pkcs11 tools.

Further reading:
* [A Practical Guide to TPM 2.0](https://link.springer.com/book/10.1007/978-1-4302-6584-9)
* [Specifications](https://trustedcomputinggroup.org/resource/tpm-library-specification/)

## RPMB (Replay Protected Memory Block)

Is implemented in eMMC storages to allow only authenticated writes to this special partition.

It is implemented in OP-TEE and used by u-boot/EFI to store the EFI variables and as secure
storage by the fTPM OP-TEE trusted application.

It ensures that RPMB is bound to the hardware-uniq key of a device. So it cannot be modified
if the eMMC is unsoldered and connected to a different device.

However the implementation status on NXP platforms is unclear at the moment: !TODO!
https://optee.readthedocs.io/en/latest/architecture/platforms/nxp.html

Further reading:
* [RPMB, a secret place inside the eMMC](https://sergioprado.blog/rpmb-a-secret-place-inside-the-emmc/)
* [RPMB in OP-TEE OS](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html#rpmb-secure-storage)

## uEFI (Unified Extensible Firmware Interface)

...is an open standard that defines the architecture of a platform firmware.
It is used for initializing hardware nad provides an interface for interacting
with the operating system.

There are several libre and closed implementation available. TianoCore EDKII
is the reference implementation.

Features:

- Running EFI applications (e.g. bootloaders, uEFI shell, ..)
- Graphics Output Protocol (GOP or EFI Framebuffer) allows early splashscreens and flickerfree boot
- Human Interface Infrastructure (HII) to abstract HID devices (keyboard, mouse, touch)
- Memory Map services
- System management mode services
- ACPI, SMBIOS and Devicetree services for hardware discovery and control
- Variable services (to share data between firmware and OS, e.g. next-boot configuration)
- Time services
- Device drivers (can continue to work after OS startup until OS driver is loaded, eg. framebuffer, network)
- Defined protocols as software interfaces between uEFI device drivers
- UEFI Capsule defines a Firmware-to-OS firmware update interface (supported by fwupd)

Further reading:

* [Specification](https://uefi.org/specs/ACPI/6.5/)
* [u-boot UEFI](https://docs.u-boot.org/en/latest/develop/uefi/index.html)


### uEFI Secure Boot

Only load drivers or OS boot loaders that are signed with an acceptable digital signature.

When enabled, it is initially placed in "setup" mode, which allows a public key
known as the "platform key" (PK) to be written to the firmware.

Than "User" mode is entered. Only UEFI drivers and OS boot loaders signed with
the platform key can be loaded.

Additional "key exchange keys" (KEK) can be added to allow other certificates.
KEKs must have a connection to the private portion of the platform key.

"Custom mode" allows additional public keys that do not match the private key.


## Boot Chain

The Boot Chain can be splitted in 3 parts:

1) Hardware: Starts at poweron/reset and includes boot-source selection and verification of
   [BL2](#bl2u-boot-spl-internal-spl-is-used-with-qemu) based on the evaluation of
   [eFuses](#efuses-not-used-with-qemu).
2) Firmware: Starts at [BL2](#bl2u-boot-spl-internal-spl-is-used-with-qemu) and includes SPL
   execution, start of [trusted-firmware-arm](#bl31trusted-firmware-arm-not-used-with-qemu),
   [OP-TEE os](#bl32op-tee-os-not-used-with-qemu) and execution of
   [BL33/u-boot proper/EFI](#bl33u-boot-properefi).
3) Operating system: Starts with [systemd-boot as boot-menu](Boot-menu/systemd-boot) and
   includes [UKI](Unified Kernel Images/UKI) selection, verification and execution,
   [Linux kernel](Linux Kernel) boot,
   [initrd](initrd) execution and [system](systemd) startup.

Further reading:
* [Hardware, i.MX HAB](https://docs.foundries.io/latest/reference-manual/security/secure-boot-imx-habv4.html)
* [Firmware, ARM SystemReady IR](https://developer.arm.com/Architectures/Arm%20SystemReady%20IR)
* [Operating system](https://0pointer.net/blog/fitting-everything-together.html)


### eFuses (not used with QEMU)

hash of first-stage bootloader signing key !TODO!


### BL2/u-boot SPL (internal SPL is used with QEMU)

Initializes RAM

Loads Devicetree into memory

Loads and starts BL31 and/or BL33


### BL31/trusted-firmware-arm (not used with QEMU)

- Initalizes TrustExecutionEnvironment and loads OP-TEE in BL32

- Acts as a hypervisor between secure and non-secure world

- Provides a Secure Monitor implementation

- Loads u-boot proper in BL33

Further Reading:
* [TF-A ReadTheDocs](https://trustedfirmware-a.readthedocs.io/en/latest/)

### BL32/OP-TEE os (not used with QEMU)

OP-TEE is a Trusted Execution Environment (TEE) designed as companion to a
non-secure Linux kernel running on Arm Cortex-A cores using the TrustZone
technology. https://optee.readthedocs.io/

Besides many other things it:

 - Provides a [RPMB storage interface](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html#rpmb-secure-storage)

 - Hosts
   [Microsofts firmware TPM2](https://github.com/microsoft/ms-tpm-20-ref/tree/main/Samples/ARM32-FirmwareTPM)
   as
   [Early TrustedApplication](https://optee.readthedocs.io/en/latest/architecture/trusted_applications.html#early-ta)

 - Inserts information about used memory areas into the devicetree


### BL33/u-boot proper/EFI

PlatformKey, KeyExchangeKey, whitelist db and blacklist dbx are stored in RPMB and are used
to verify executed EFI binaries.

OP-TEE hosted fTPM is used as TPM2 on i.MX platforms.

swtpm emulation is used as TPM2 on QEMU emulated systems.

TPM2 is used for boot measurements into PCR registers:

- of loaded EFI binary
- Value of EFI variables (e.g. SecurebootEnabled)

#### Example use-case:

GPL3 requires us to enable users to exchange GPL3 software.

A user disables Secureboot to load its own Linux and wants
to access a cloud service that shall be only reachable by
cloud-vendor verified software.

The developers of the device create secrets like Private keys or certificates
inside the TPM2 and bind the unlock condition to TPM2 PCR register 7.
(PCR register 7 reflects the secure boot status of a device)

So the secrets needed to access the cloud service are only accessible if booted
with properly signed components.


#### Key generation

Create Platform Key (PK), Key exchange Key (KEK), db whitelist database

Start from "Install the required tools on your host" and create the keys.

DO NOT create a db certificate. Use the mkosi.crt as db.crt and mkosi.key as db.key.
Continue with cert-to-efi-sig-list and sign-efi-sig-list for creating whitelist database.

Further Reading:
* [u-boot UEFI](https://docs.u-boot.org/en/latest/develop/uefi/uefi.html)


### Boot-menu/systemd-boot

EFI starts the signed [systemd-boot](https://www.freedesktop.org/software/systemd/man/latest/systemd-boot.html#) EFI binary.
It follows the [UAPI boot-loader specification](https://uapi-group.org/specifications/specs/boot_loader_specification/)


### Unified Kernel Images/UKI

Are also signed EFI binaries verificated and started by systemd-boot.

A UKI contains a stub, that is able to e.g.
 - Write an embedded splash screen to an EFI Framebuffer
 - Loads the embedded initrd and kernel image
 - Executes the kernel boot

Further Reading:
* [UAPI UKI Specification](https://uapi-group.org/specifications/specs/unified_kernel_image/)


### Linux Kernel

Loads drivers required to run systemd in the initrd.

The kernel currently needs to be patched to support routing RPMB read/write requests
from OP-TEE directly in the kernel.

The required patches are here:
https://lore.kernel.org/lkml/CAHUa44E0bLYHzoGs3onu6sK5dwXB=1t-GsFWt096z+u4aN6R1g@mail.gmail.com/

Apply them to a current mainline Linux kernel, build with:

```
$ ARCH=arm64 CROSS_COMPILE=aarch64-gnu-linux- make -j`nproc` defconfig
$ ARCH=arm64 CROSS_COMPILE=aarch64-gnu-linux- make -j`nproc` bindeb-pkg
```

Copy the .deb package to os-image/pkgs, Add PkgDirectories=pkgs to mkosi.conf
and replace the Debian linux-image-arm64 by the name of your package.


### initrd

systemd is already used in the initrd. It is able to resize partitions with systemd-repart
and log boot measurements in the TPM2 PCR registers.

At least systemd v256 is required to have a
[tpm2.target/generator](https://github.com/systemd/systemd/commit/4e1f0037b85d1b3c272e13862f44eb35844a18b1)

Further Reading:
* [systemd-bootup Specification](https://www.freedesktop.org/software/systemd/man/latest/bootup.html#Bootup%20in%20the%20initrd)

### systemd

systemd continues measuring boot to the TPM2.


### Application on a encrypted Volume

!TODO!

## Boot measurements

Measured Boot is the process of computing and securely recording hashes of code and critical data
at each stage in the boot chain before the code/data is used.

These measurements can be leveraged by other components in the system to implement a complete
attestation system. For example, they could be used to enforce local attestation policies
(such as releasing certain platform keys or not), or they could be securely sent to a remote
challenger a.k.a. verifier after boot to attest to the state of the code and critical-data.

Measured Boot does not authenticate the code or critical-data, but simply records what
code/critical-data was present on the system during boot.
[Source](https://trustedfirmware-a.readthedocs.io/en/latest/design_documents/measured_boot.html)

The measurement hashes can be stored in the _Platform Configuration Register (PCR)_ of a TPM.
A TPM 2.0 typically provides 24 PCRs of which 8 are owned by the firmware and 8 can be used
by the OS. The common PCR assignments in Linux are specified by the UAPI group:
https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/


## systemd-sysupdate and systemd-repart

sysupdate, maintained by the systemd project, implements file, directory or partition based updates schemes.
It also supports parallel installed version of specific resources in A/B style like RAUC.

An example A/B style image layout could be like following:
- 1 EFI system partition
- 2 /usr partition, immutable and verity-protected (A+B)
- 2 /usr-verity partition (A+B)
- 1 rootfs used by system A and B, e.g for system configuration files

The EFI system partition contains all Unified kernel images (UKI, = kernel+kernelcmd+initrd+devicetree+etc.)

The read-only /usr partition contains all kernel modules, binaries, libraries, default configurations, etc...

The /usr-verity partition is for verifying the /usr partition

The read-writeable rootfs contains the rest.

Alternatively, a newly deployed image can ship an EFI system partition, system A of /usr and /usr-verity partition.
This keeps the image small. On first boot empty space for system B /usr and /usr-verity and the rootfs will be created.
Additionally the rootfs can be enlarged to the maximum size of the backing storage device. All done with systemd-repart.

To build an image with this partition layout use the 'verity' profile:

```
$ mkosi --profile=verity build
```

A system update will then install a new UKI image into the EFI partition, a new /usr and /usr-verity partition into
the partitions owned by system B. On next boot, systemd-boot (executing after the firmware, here u-boot) will pick
the newest UKI image and boot it. The corresponding /usr and /usr-verity partition will be automatically found via
the usrhash= kernel parameter by systemd-veritysetup-generator running in the initrd.

A much more detailed description can be found here: https://0pointer.net/blog/fitting-everything-together.html

The boot assessment for reverting back to a working system, e.g. like an A+B system is described in detail here:

* https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/


# Try it out!

## Build a generic operating system image

1) Use the following instructions on a Debian/bookworm system.
   Ensure that bookworm-backports are enabled
   (https://backports.debian.org/Instructions/#index2h2).
   systemd is required to be installed from backports:

```
$ sudo apt install -t bookworm-backports systemd systemd-boot
```

   Also some additional tools are needed to generate the image:

```
$ sudo apt install -y \
        bubblewrap \
        cifs-utils \
        cpio \
        dosfstools \
        dpkg-dev \
        erofs-utils \
        kmod \
        libtpm2-pkcs11-1 \
        libtss2-mu-4.0.1-0t64 \
        libtss2-rc0 \
        mkosi \
        mtools \
        openssl \
        python3-cryptography \
        python3-pefile \
        sbsigntool \
        udev \
        zstd
```

Generate a set of keys and certs use for signing

```
$ mkosi genkeys
```


## On a Verdin Board with i.MX8MM

0) Build the image

```
$ mkosi -f --profile verity build
```

These instructions are valid for ARM64 Toradex Verdin Board with i.MX8MM
It uses a firmware TPM running in OP-TEE and u-boot with EFI support as Firmware.

0) Write the OS image to a SDCard. Insert the SDCard to your PC and copy it with dd

```
$ cd mkosi-conf
$ sudo if=build-iris_1.0/iris_1.0.raw of=/dev/mmcblk0 bs=5M; sync
```

1) Use flash.bin and uuu.auto built by https://github.com/mt-at-mt/build-efi-firmware/blob/devel/build.sh

```
$ sudo apt install uuu
$ sudo uuu .

```

2) Do a recovery boot by pressing the recovery button and reset on the board.
   Interrupt in the bootloader and use fastboot to flash the firmware to the eMMC.

```
Hit any key to stop autoboot:  2
=>
```

3) First boot configuration

```
...
Filename '0A00020F.img'.
Load address: 0x40400000
Loading: *
TFTP error: 'Access violation' (2)
Not retrying...
No more bootdevs
---  -----------  ------  --------  ----  ------------------------  ----------------
(0 bootflows, 0 valid)
=>
```

The EFI storage is not initialized. eficonfig needs to be called and quit, like this:

```
=> eficonfig

  ** UEFI Maintenance Menu **

      Add Boot Option
      Edit Boot Option
      Change Boot Order
      Delete Boot Option
      SecureBoot Configuration 
      Quit
```

Select 'Add Boot Option'

```
  ** Add Boot Option **

      Description:
      File:
      Initrd File:
      Optional Data:
      Save
      Quit
```

Select 'Quit'

```
  ** UEFI Maintenance Menu **

      Add Boot Option
      Edit Boot Option
      Change Boot Order
      Delete Boot Option
      SecureBoot Configuration 
      Quit
```

Select 'Quit' again and reset the device

```
=> reset
```


4) Verify boot

Now the system shall first-boot.

The system can be used as 'root' with password 'root'.

To verify the boot status use bootctl:

```
root@iris:~# bootctl
Couldn't find EFI system partition. It is recommended to mount it to /boot or /efi.
Alternatively, use --esp-path= to specify path to mount point.
System:
      Firmware: UEFI 2.100 (Das U-Boot 8228.256)
 Firmware Arch: aa64
   Secure Boot: disabled (setup)
  TPM2 Support: yes
  Measured UKI: yes
  Boot into FW: not supported

Current Boot Loader:
      Product: systemd-boot -g825c26b^
     Features: ✓ Boot counting
               ✓ Menu timeout control
               ✓ One-shot menu timeout control
...

root@iris:~# reboot
```

Secure Boot is still disabled, because no keys are deployed in u-boot/EFI.


5) Enable EFI Secure Boot

Copy PK.auth, KEK.auth and mkosi.auth from the 'os-image' folder to the EFI partition
of the SDCard. In u-boot load it from there:
```
starting USB...
No working controllers found
Hit any key to stop autoboot:  2
=>
=> fatload mmc 1:1 $kernel_addr_r PK.auth
=> setenv -e -nv -bs -rt -at -i $kernel_addr_r:$filesize PK
=> fatload mmc 1:1 $kernel_addr_r KEK.auth
=> setenv -e -nv -bs -rt -at -i $kernel_addr_r:$filesize KEK
=> fatload mmc 1:1 $kernel_addr_r mkosi.auth
=> setenv -e -nv -bs -rt -at -i $kernel_addr_r:$filesize db
=> bootefi bootmgr
...
```

6) Check Secure Boot status again

```
root@iris:~# mount /dev/disk/by-partlabel/esp /boot
root@iris:~# bootctl
Couldn't find EFI system partition. It is recommended to mount it to /boot or /efi.
Alternatively, use --esp-path= to specify path to mount point.
System:
      Firmware: UEFI 2.100 (Das U-Boot 8228.256)
 Firmware Arch: aa64
   Secure Boot: enabled (user)
  TPM2 Support: yes
  Measured UKI: yes
  Boot into FW: not supported

Current Boot Loader:
      Product: systemd-boot -g825c26b^
     Features: ✓ Boot counting
               ✓ Menu timeout control
               ✓ One-shot menu timeout control
               ✓ Default entry control
               ✓ One-shot entry control
               ✓ Support for XBOOTLDR partition
               ✓ Support for passing random seed to OS
               ✓ Load drop-in drivers
               ✓ Support Type #1 sort-key field
               ✓ Support @saved pseudo-entry
               ✓ Support Type #1 devicetree field
               ✓ Enroll SecureBoot keys
               ✓ Retain SHIM protocols
               ✓ Menu can be disabled
               ✓ Boot loader sets ESP information
         Stub: systemd-stub -g825c26b^
     Features: ✓ Stub sets ESP information
               ✓ Picks up credentials from boot partition
               ✓ Picks up system extension images from boot partition
               ✓ Picks up configuration extension images from boot pa
rtition
               ✓ Measures kernel+command line+sysexts
               ✓ Support for passing random seed to OS
               ✓ Pick up .cmdline from addons
               ✓ Pick up .cmdline from SMBIOS Type 11
               ✓ Pick up .dtb from addons
          ESP: /dev/disk/by-partuuid/e7ffe949-766f-4d92-8e44-da23be07559e
         File: └─//EFI/BOOT/BOOTAA64.EFI

Random Seed:
 System Token: not set
       Exists: yes

Available Boot Loaders on ESP:
          ESP: /boot (/dev/disk/by-partuuid/e7ffe949-766f-4d92-8e44-da23be07559e
)
         File: ├─/EFI/systemd/systemd-bootaa64.efi (systemd-boot -g825c2
6b^)
               └─/EFI/BOOT/BOOTAA64.EFI (systemd-boot -g825c26b^)

No boot loaders listed in EFI Variables.

Boot Loader Entries:
        $BOOT: /boot (/dev/disk/by-partuuid/e7ffe949-766f-4d92-8e44-da23be07559e
)
        token: iris

Default Boot Loader Entry:
         type: Boot Loader Specification Type #2 (.efi)
        title: Debian GNU/Linux trixie/sid
           id: iris-6.6.25-iris_rt_defconfig-4bada3e4b9b33b2ee2185043c87b6ca3b2d46c06644ba0fcf89425f8dc093c2f.efi
       source: /boot//EFI/Linux/iris-6.6.25-iris_rt_defconfig-4bada3e4b9b33b2ee2185043c87b6ca3b2d46c06644ba0fcf89425f8dc093c2f.efi
     sort-key: iris
      version: 1.0
        linux: /boot//EFI/Linux/iris-6.6.25-iris_rt_defconfig-4bada3e4b9b33b2ee2185043c87b6ca3b2d46c06644ba0fcf89425f8dc093c2f.efi
      options: usrhash=4bada3e4b9b33b2ee2185043c87b6ca3b2d46c06644ba0fcf89425f8dc093c2f efi=runtime rng_core.default_quality=1000 systemd.tpm2_wait=true

## Upgrades with systemd-sysupdate

If update files/partitions for a set of sysupdate config files are found in sysupdate.d/ directory, then following output will be seen when systemd-sysupdate is queried to list a possible update :
```
root@iris:/mnt# /usr/lib/systemd/systemd-sysupdate --json pretty list
Automatically discovered root block device '/dev/mmcblk0'.
Automatically discovered root block device '/dev/mmcblk0'.
Discovering installed instances…
Discovering available instances…
Determining installed update sets…
Determining available update sets…
[
	{
		"" : "↻",
		"version" : "1.1",
		"installed" : " ",
		"available" : "✓",
		"assessment" : "candidate"
	},
	{
		"" : "●",
		"version" : "1.0",
		"installed" : "✓",
		"available" : " ",
		"assessment" : "current"
	}
]
```
Note: The MatchPattern= expression in the [Source] section of sysupdate.d config files has to
match the file name of the to-be-deployed file/partition.

Afterwards, execute 
```
/usr/lib/systemd/systemd-sysupdate update
```
which will then update the set defined in sysupdate.d/ directory.


### LUKS and TPM2

A description is available here:

https://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html

It is not possible to integrate this into the mkosi image.
Deployment needs to be done during bringup and upgrade.


## How to use pkcs11-tool

Below, will be examples how to use tpm2-pkcs11 with pkcs11-tool

1) Set up an alias, make sure the libtpm2_pkcs11.so path is correct.

```
$ alias tpm2pkcs11-tool='pkcs11-tool --module /usr/lib/aarch64-linux-gnu/pkcs11/libtpm2_pkcs11.so.1'

```

2) Initialize the token with the specified PIN and Label

```
$ tpm2pkcs11-tool --init-token --so-pin=146878 --init-pin --pin=984235 --label=tng

```

3) list previous token and slots 

```
$ tpm2pkcs11-tool --list-token-slots

Available slots:
Slot 0 (0x1): tng
  token label          : tng
  token manufacturer   : IBM
  token model          : SW    TPM
  token flags          : login required, rng, token initalized, PIN initialized
  hardware version     : 1.64
  firmware version     : 25.35
  serial num           : 000000000000000000
  pin min/max          : 0/128
Slot 1 (0x2):   uninitialized

```

4) Generate keypair with specified PIN and label

```
$ tpm2pkcs11-tool -l --pin=984235 --keypairgen --key-type EC:secp384r1 --id 0 --label my-ecc-keypair
Using slot 0 with a present token (0x1)
Key pair generated:
Private Key Object; EC
  label:      my-ecc-keypair
  ID:         00
  Usage:      decrypt, sign, derive
  Access:     sensitive, always sensitive, never extractable, local
  Allowed mechanisms: ECDSA,ECDSA-SHA1,ECDSA-SHA256,ECDSA-SHA384,ECDSA-SHA512
Public Key Object; EC  EC_POINT 384 bits
  EC_POINT:   046104c43b74b80c14fb391e7b2d0587cc09e565acdbee69cc3f4336c6c406465bf8f7691822b3bdb82263f62281834bb8fd22cb84d4155a0dd390487d5b82dfc27597cebc5e43eb0851504fc270c87d463b78611b3cf43ab7e8defb52b87a53739317
  EC_PARAMS:  06052b81040022
  label:      my-ecc-keypair
  ID:         00
  Usage:      encrypt, verify, derive
  Access:     local

```

5) Export key

```
$ yaml_rsa0=$(tpm2_ptool export --label=tng --key-label=my-ecc-keypair --userpin=984235)
$ auth_rsa0=$(echo "$yaml_rsa0" | grep "object-auth" | cut -d' ' -f2-)
```

6) Use the key in the previous step to generate a CSR

```
$ openssl req -new -provider tpm2 -provider base \
    -key my-ecc-keypair.pem \
    -passin "pass:$auth_rsa0" \
    -subj "/C=US/ST=New York/L=Brooklyn/O=MT Company/CN=GoodMt.com" \
    -out mttest.csr
```

7) Double check csr file

```
$ openssl req -text -noout -verify -in mttest.csr
Certificate request self-signature verify OK
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C = US, ST = New York, L = Brooklyn, O = MT Company, CN = GoodMt.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:c4:3b:74:b8:0c:14:fb:39:1e:7b:2d:05:87:cc:
                    09:e5:65:ac:db:ee:69:cc:3f:43:36:c6:c4:06:46:
                    5b:f8:f7:69:18:22:b3:bd:b8:22:63:f6:22:81:83:
                    4b:b8:fd:22:cb:84:d4:15:5a:0d:d3:90:48:7d:5b:
                    82:df:c2:75:97:ce:bc:5e:43:eb:08:51:50:4f:c2:
                    70:c8:7d:46:3b:78:61:1b:3c:f4:3a:b7:e8:de:fb:
                    52:b8:7a:53:73:93:17
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        Attributes:
            (none)
            Requested Extensions:
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:65:02:31:00:cf:1e:07:1c:31:8a:ac:e4:37:90:cf:2f:0d:
        d4:c2:13:18:b6:97:64:0c:24:8c:7f:aa:56:30:a8:a3:f9:51:
        b3:ee:3d:24:bc:ee:34:b7:f8:a0:d3:a8:35:25:91:4e:9c:02:
        30:57:0d:fe:a5:e1:52:91:2d:99:b4:33:9b:d6:2d:ba:d7:00:
        87:d4:1f:6b:10:69:62:cc:1a:44:15:a4:09:8d:d3:09:de:9f:
        22:dc:de:e4:31:82:95:e0:3e:f4:26:ce:24
```


# Terminology

## certificate

Source [wikipedia.org](https://en.wikipedia.org/wiki/Public_key_certificate)

In cryptography, a public key certificate, also known as a digital certificate or identity
certificate, is an electronic document used to prove the validity of a public key.

The certificate includes the public key and information about it, information about the identity
of its owner (called the subject), and the digital signature of an entity that has verified the
certificate's contents (called the issuer). If the device examining the certificate trusts the
issuer and finds the signature to be a valid signature of that issuer, then it can use the included
public key to communicate securely with the certificate's subject.


##Device Locking/Unlocking

A locked device is only able to execute signed code from trusted organizations. It ensures that
no 3rd party code can be executed.

On a unlocked device a user takes the responsibility on the device by its own. The user is able
to execute any software or limit the execution to self signed code.

A locked device can be turned into an unlocked with a key provided by the vendor of the device.

The vendor could use device specific keys to be aware of potential unlocked devices. It might be
possible to form statements, like the device warranty is lost if the unlock key was used.


## sealed

Sealed information is only available in a trusted environment. E.g. on a locked device
booted with verified components.


## secret

A secret is a piece of information that shall only be accesible to authorized readers.

Examples for secrets are:
 - Certificates used to authenticate access to a cloud servce
 - A symmetric key used for encryption or decription of files, filesystems or network traffic
 - The binary code of a properitary application that includes intelectual property


## Tivoization

Source [wikipedia.org](https://en.wikipedia.org/wiki/Tivoization)

Tivoization is the practice of designing hardware that incorporates software under the terms of a
copyleft software license like the GNU General Public License (GNU GPL), but uses hardware
restrictions or digital rights management (DRM) to prevent users from running modified versions of
the software on that hardware.
Richard Stallman of the Free Software Foundation (FSF) coined the term in reference to TiVo's use of
GNU GPL licensed software on the TiVo brand digital video recorders, which actively block modified
software by design. Stallman believes this practice denies users some of the freedom that the
GNU GPL was designed to protect. The FSF refers to tivoized hardware as "proprietary tyrants".

The Free Software Foundation explicitly forbade tivoization in version 3 of the GNU General Public
License.


## verified boot

Verified Boot strives to ensure all executed code comes from a trusted source (usually device OEMs),
rather than from an attacker or corruption. It establishes a full chain of trust, starting from a
hardware-protected root of trust to the bootloader, to the boot partition and other verified
partitions.

During device boot up, each stage verifies the integrity and authenticity of the next stage before
handing over execution.
