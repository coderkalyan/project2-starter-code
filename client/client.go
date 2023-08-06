package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

type Header struct {
    Filename string
    HeaderID userlib.UUID
    HeaderKey []byte
    IsOwned bool 
}

type User struct {
	Username string
    rootKey []byte
    AuthKey []byte
    encryptionKey []byte
    macKey []byte

    publicKey userlib.PKEEncKey
    PrivateKey userlib.PKEDecKey

    Headers []Header
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username
    userdata.rootKey = userlib.Argon2Key([]byte(password), []byte(username), 256)
    userdata.AuthKey, err = userlib.HashKDF(userdata.rootKey, []byte("authentication"))
    if err != nil {
        return nil, err
    }
    userdata.encryptionKey, err = userlib.HashKDF(userdata.rootKey, []byte("encryption"))
    if err != nil {
        return nil, err
    }
    userdata.macKey, err = userlib.HashKDF(userdata.rootKey, []byte("hmac"))
    if err != nil {
        return nil, err
    }

    userdata.publicKey, userdata.PrivateKey, err = userlib.PKEKeyGen()
    if err != nil {
        return nil, err
    }

    storageId, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
    if err != nil {
        return nil, err
    }

    plaintext, err := json.Marshal(userdata)
    if err != nil {
        return nil, err
    }

    iv := userlib.RandomBytes(16)
    ciphertext := userlib.SymEnc(userdata.encryptionKey, iv, plaintext)
    sum, err := userlib.HMACEval(userdata.macKey, ciphertext)
    if err != nil {
        return nil, err
    }
    ciphertext = append(ciphertext, sum...)

    userlib.DatastoreSet(storageId, ciphertext)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
    expectedRootKey := userlib.Argon2Key([]byte(password), []byte(username), 256)
    expectedAuthKey, err := userlib.HashKDF(expectedRootKey, []byte("authentication"))
    if err != nil {
        return nil, err
    }

    storageId, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
    if err != nil {
        return nil, err
    }

    ciphertext, exists := userlib.DatastoreGet(storageId)
    if !exists {
        // TODO: error
        fmt.Println("unknown username")
    }

    encryptionKey, err := userlib.HashKDF(expectedRootKey, []byte("encryption"))
    if err != nil {
        return nil, err
    }
    macKey, err := userlib.HashKDF(expectedRootKey, []byte("hmac"))
    if err != nil {
        return nil, err
    }

    expectedSum := ciphertext[len(ciphertext) - 64:]
    ciphertext = ciphertext[:len(ciphertext) - 64]
    actualSum, err := userlib.HMACEval(macKey, ciphertext)
    if err != nil {
        return nil, err
    }

    if (!userlib.HMACEqual(expectedSum, actualSum)) {
        // TODO: error
        fmt.Printf("expected %s != actual %s\n", expectedSum, actualSum)
    }

    plaintext := userlib.SymDec(encryptionKey, ciphertext)
	var userdata User
    err = json.Unmarshal(plaintext, &userdata)
    if err != nil {
        return nil, err
    }

    if (!userlib.HMACEqual(expectedAuthKey, userdata.AuthKey)) {
        // TODO: error
        fmt.Printf("expected %s != actual %s\n", expectedAuthKey, userdata.AuthKey)
    }

    userdata.rootKey = expectedRootKey
    userdata.encryptionKey = encryptionKey
    userdata.macKey = macKey

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
