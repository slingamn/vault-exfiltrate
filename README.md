vault-exfiltrate
================

`vault-exfiltrate` is a proof-of-concept for extracting the AES master and session keys from an unsealed [Hashicorp Vault](https://www.vaultproject.io/) process, or from a core dump of one.

    $ pgrep vault
    42426
    $ vault-exfiltrate extract 42426 keyring_file | tee keyring.json
    {"MasterKey":"cvS8jiPVfiv4sRUn5k8jr65mbG1f6aY8PE+/pEAH/yE=","Keys":[{"Term":1,"Version":1,"Value":"qvLGtPnk5IgTWPi096rmplucaNSGXwyJkxvqrDnUbnY=","InstallTime":"2021-08-11T04:47:40.384044716Z","encryptions":25}],"RotationConfig":{"Disabled":false,"MaxOperations":3865470566,"Interval":0}}
    $ vault-exfiltrate decrypt keyring.json logical/90828c10-fb92-12b8-78ca-a262f150b322/test_secret ciphertext_file
    {"secret_name":"secret_value"}

Its main purpose is to demonstrate the limitations of Vault's "two-man rule" threat model (and the Shamir secret-sharing scheme more generally) and inform discussion about potential hardening techniques for Vault.

## Vault and its security model

[Vault](https://www.vaultproject.io/) is software intended to centralize and unify handling of secret data across an organization's personnel and networked services. These aspects of its [security model](https://www.vaultproject.io/docs/internals/security.html) are relevant:

1. Vault supports multiple datastores (e.g., MySQL, Zookeeper, and DynamoDB) for persisting long-lived secrets; all such secrets are stored under authenticated encryption (AES-GCM in the current implementation) with a session key.
1. The session keys are stored in the same backend with the same algorithm, but with a different key: the *master key*. The datastore entry holding the encrypted session keys is called the *keyring*. Both master and session keys can be [rotated](https://www.vaultproject.io/docs/internals/rotation.html).
1. By default, the master key is split into multiple shares with the [Shamir secret sharing scheme](https://en.wikipedia.org/wiki/Shamir's_Secret_Sharing). Shares are then distributed among operators.
1. When started, a Vault process is in the non-functional "sealed" state, meaning it has no access to the master key or the session keys. Operators "unseal" the process by inputting their shares, at which point the master key can be reconstructed and the session keys retrieved and decrypted. At this point, the Vault process has the master key and the session keys stored in memory.

I believe there is a contradiction between the following two [claims](https://www.vaultproject.io/docs/internals/security.html):

1. Vault's threat model explicitly excludes attacks based on memory analysis of an unsealed Vault process: "if an attacker is able to inspect the memory state of a running Vault instance then the confidentiality of data may be compromised."
1. However, the documentation suggests that the use of the Shamir scheme provides protection against malfeasance by a single operator: "Vault supports using a [Two-man rule](https://en.wikipedia.org/wiki/Two-man_rule) for unsealing using Shamir's Secret Sharing technique [....] The risk of distributing the master key is that a single malicious actor with access to it can decrypt the entire Vault."

`vault-exfiltrate` is intended to demonstrate that instead:

1. In a standard Linux environment, it's straightforward for a malicious administrator (or an attacker with root-level access) to obtain the master and session keys.
1. Most real-world deployments of the Shamir scheme implicitly require a trusted third party: the environment in which the secret is reconstructed, and which is then responsible for preventing the shareholders from stealing the secret.

## Compilation

To compile the project, clone the repository, [install the Go language if necessary](https://golang.org/dl/), then run `go build`; this will produce a binary named `vault-exfiltrate` in the working directory. For cross-compilation, you can add the usual environment variables, e.g. `GOOS=darwin GOARCH=arm64` to build for the Apple M1.

## Usage

`vault-exfiltrate` has multiple modes. `vault-exfiltrate extract` takes the PID of a running unsealed `vault` process as its first argument, and a file containing the exact binary ciphertext of the keyring as its second argument. The keyring is stored at the path `core/keyring` within Vault's logical key-value namespace; the method of retrieving the data will depend on the physical storage backend. For example, the `file` storage backend stores the keyring at the relative filesystem path `core/_keyring`, wrapped in JSON and base64; the `zookeeper` backend stores it as the data of the `core/_keyring` node; and the `mysql` backend stores it in the table row with `vault_key = 'core/keyring'`. If successful, it outputs the JSON plaintext of the keyring, including the master key and all active session keys.

`vault-exfiltrate extract-core` is similar, except that it takes the filename of an ELF core dump of an unsealed `vault` process instead of the PID of a running process. A suitable core file can be obtained with the [gcore](http://man7.org/linux/man-pages/man1/gcore.1.html) utility, which is part of `gdb`.

`vault-exfiltrate decrypt` takes three arguments: a file containing the JSON keyring plaintext produced by `extract`, the logical path of an entry in the storage backend, and a file containing the exact binary ciphertext of the entry. If successful, it outputs the plaintext of the entry.

`vault-exfiltrate split` and `vault-exfiltrate combine` provide direct access to the Shamir secret sharing implementation used by Vault. `vault-exfiltrate split` takes two arguments: the base64 encoding of a secret, and the number of shares to split it into, and outputs the base64 encoding of the shares. `vault-exfiltrate combine` takes n arguments, where n >= 2: n shares of a secret split with threshold n, and outputs the base64 encoding of the reconstructed secret. takes two arguments: a file containing the JSON keyring plaintext, and a threshold number of shares *n*.

`split` can be used as a key recovery tool: if the original unseal shares have been lost, but an unsealed `vault` process is still running,  it can be used to produce new shares. The shares can then be used to [rotate the master key](https://www.vaultproject.io/guides/rekeying-and-rotating.html), or to [generate a new root token](https://www.vaultproject.io/guides/generate-root.html), which provides [unrestricted application-level access](https://www.vaultproject.io/docs/concepts/tokens.html#root-tokens) to Vault. (Note that for both of these use cases, the threshold number must agree with the number Vault was originally configured to use; `vault rekey` can be used to change the threshold.) The value to split depends on the version of Vault. In versions prior to 1.3, one splits the master key itself. In [versions 1.3 and later](https://github.com/hashicorp/vault/pull/7694), one must first obtain and decrypt the value of `core/shamir-kek`, then split it. Here's an example using the `file` storage backend:

```
$ cat /opt/vault/data/core/_shamir-kek
{"Value":"AAAAAQJTO4su/Df1zgrZj4bGv6zg5alj3COLGHWZpQk7+M5LyrU4Ghj26waz64NC3AhcXKbGO2oisBCxjobNS1c="}
$ echo AAAAAQJTO4su/Df1zgrZj4bGv6zg5alj3COLGHWZpQk7+M5LyrU4Ghj26waz64NC3AhcXKbGO2oisBCxjobNS1c= | base64 -d > shamir-kek-decoded
$ ./vault-exfiltrate decrypt keyring.json core/shamir-kek ./shamir-kek-decoded > shamir-kek-decrypted
$ base64 shamir-kek-decrypted
IWRLtGahZj12BzCXqahSrO6zStlNUg20kiMgwGc2EQA=
$ ./vault-exfiltrate split IWRLtGahZj12BzCXqahSrO6zStlNUg20kiMgwGc2EQA= 3
pvZuvvOrO13IBSftdJTrYR0zVWhla33vcx/4ml3NNR53
w3d7CnDgXsDHEkcUaqyywegRZjqy/L+xGoz9lBQJOTQW
29G+TcF4hlTlbSzhAi+XufKMlAdrWhirN8AvBLktdU89
```

## Implementation

Originally, I tried to use [delve](https://github.com/derekparker/delve) to retrieve the master key. However, `delve core` had difficulty interpreting the core dumps produced by `gcore`. Fortunately, testing candidate AES-GCM keys is very cheap; my hardware can perform approximately a million guesses per second. The approach implemented here is to enumerate all read-write regions in the process memory or core file, then try every 256-bit sequence aligned to a 64-bit boundary. This should take between seconds and tens of seconds in the typical case.

## Recommendations

Vault should not be used to protect long-lived secrets that cannot be rotated. This is hinted at in some Vault documentation, in particular for [PKI](https://www.vaultproject.io/docs/secrets/pki/index.html): "Vault storage is secure, but not as secure as a piece of paper in a bank vault [....] If your root CA is hosted outside of Vault, don't put it in Vault as well; instead, issue a shorter-lived intermediate CA certificate and put this into Vault."

It is possible to harden Vault against this attack:

1. By default, Go programs [should not produce core dumps on crashes](https://golang.org/pkg/runtime/). However, it's conceivable that a bug or exploit in the Go runtime or in dynamically linked native libraries could result in a core dump being written to disk, at which point it could be exposed deliberately or accidentally. Vault can be prevented from dumping core on crashes via the standard resource limit technique (ensuring `RLIMIT_CORE` is set to `0`). This recommendation now appears in Vault's [production hardening guide](https://www.vaultproject.io/guides/production.html).
1. An attacker with root privileges can still read process memory, either by raising the core limit with [prlimit(1)](http://man7.org/linux/man-pages/man1/prlimit.1.html) or by using the kernel's `ptrace(2)` functionality. It's possible in principle to modify the Linux kernel to permanently disable both core dumps and `ptrace(2)`. In order not to have to build multiple versions of the kernel, it would probably be best to implement this as a kernel command-line option.

I believe these measures, combined with secure boot and restrictions on loadable kernel modules, would block all key recovery attacks against unsealed `vault` processes. However, a persistent attacker with root access doesn't need to read the keys from an unsealed instance, but can instead backdoor userspace binaries (`vault` itself, or `sshd` or a shell) and wait for the next time operators perform an unseal. It's an open question whether Vault can be feasibly deployed under something like the [ChromeOS verified boot model](https://www.chromium.org/chromium-os/chromiumos-design-docs/verified-boot), with a chain of trust that starts in the hardware and then verifies the kernel and finally all relevant parts of the userland.
