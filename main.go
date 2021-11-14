package main

import (
	"cloud.google.com/go/datastore"
	kms "cloud.google.com/go/kms/apiv1"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"hash/crc32"
	"log"
	"time"
)

type Card struct {
	Number          string
	CardHolderName  string
	ExpirationMonth string
	ExpirationYear  string
}

type Token struct {
	Id               string    `datastore:"id" json:"id,omitempty"`
	MerchantId       string    `datastore:"merchant_id" json:"merchant_id,omitempty"`
	Provider         string    `datastore:"provider" json:"provider,omitempty"`
	CardId           string    `datastore:"card_id,noindex" json:"card_id,omitempty"`
	TokenProvider    string    `datastore:"token_provider,noindex" json:"token_provider,omitempty"`
	DataCypheredCard []byte    `datastore:"data_card,noindex" json:"data_card,omitempty"`
	Date             time.Time `datastore:"date,noindex" json:"-"`
}

var kmsClient *kms.KeyManagementClient
var datastoreClient *datastore.Client

func main() {

	initClients()

	bytes, err := createDataCard()
	if err != nil {
		log.Panicf("there is error: %v\n", err)
	}

	dataEncrypted, err := encrypt(bytes)
	if err != nil {
		log.Panicf("there is error: %v\n", err)
	}

	token := Token{
		Id:               uuid.New().String(),
		MerchantId:       "teste-artur",
		Provider:         "provider",
		DataCypheredCard: dataEncrypted,
		Date:             time.Now().UTC(),
	}

	log.Printf("id: %s\n", token.Id)

	err = save(token)
	if err != nil {
		log.Panicf("there is error: %v\n", err)
	}

	data, err := decrypt(dataEncrypted)
	if err != nil {
		log.Panicf("there is error: %v\n", err)
	}
	
	newCard := Card{}
	err = json.Unmarshal(data, &newCard)
	if err != nil {
		log.Panicf("there is error: %v\n", err)
	}

	fmt.Println(newCard)

	token, err = load(token.Id)
	if err != nil {
		log.Panicf("there is error: %v\n", err)
	}

	data, err = decrypt(token.DataCypheredCard)
	if err != nil {
		log.Panicf("there is error: %v\n", err)
	}

	newCard = Card{}
	err = json.Unmarshal(data, &newCard)
	if err != nil {
		log.Panicf("there is error: %v\n", err)
	}

	fmt.Println(newCard)
}

func save(token Token) error {
	_, err := datastoreClient.Put(context.Background(), generateKey(token.Id), &token)
	if err != nil {
		log.Printf("there is error: %v\n", err)
	}
	return err
}

func load(id string) (Token, error) {
	var token Token
	if err := datastoreClient.Get(context.Background(), generateKey(id), &token); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return Token{}, nil
		}
		return Token{}, err
	}
	return token, nil
}

func initClients() {
	initClientKMS()
	initClientDatastore()
}

func initClientDatastore() {
	client, err := datastore.NewClient(context.Background(), "projectId")
	if err != nil {
		log.Panicf("failed to setup client: %v\n", err)
	}
	datastoreClient = client
}

func createDataCard() ([]byte, error) {
	bytes, err := json.Marshal(&Card{
		Number:          "4024007129267307",
		CardHolderName:  "JOÃO DOS SANTOS ANDRÉ",
		ExpirationMonth: "10",
		ExpirationYear:  "30",
	})
	return bytes, err
}

func initClientKMS() error {
	ctx := context.Background()
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Panicf("failed to setup client: %v\n", err)
	}
	kmsClient = c
	return err
}

func encrypt(message []byte) ([]byte, error) {
	// Convert the message into bytes. Cryptographic plaintexts and
	// ciphertexts are always byte arrays.
	plaintext := message

	// Optional but recommended: Compute plaintext's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	plaintextCRC32C := crc32c(plaintext)

	// Build the request.
	req := &kmspb.EncryptRequest{
		Name:            "projects/projectId/locations/global/keyRings/your-ring/cryptoKeys/your-key",
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(plaintextCRC32C)),
	}

	// Call the API.
	result, err := kmsClient.Encrypt(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %v\n", err)
	}

	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if result.VerifiedPlaintextCrc32C == false {
		return nil, fmt.Errorf("Encrypt: request corrupted in-transit")
	}
	if int64(crc32c(result.Ciphertext)) != result.CiphertextCrc32C.Value {
		return nil, fmt.Errorf("Encrypt: response corrupted in-transit")
	}

	fmt.Printf("Encrypted ciphertext: %s\n", result.Ciphertext)
	return result.Ciphertext, nil

}

func decrypt(ciphertext []byte) ([]byte, error) {
	// Optional, but recommended: Compute ciphertext's CRC32C.
	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	ciphertextCRC32C := crc32c(ciphertext)

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:             "projects/projectId/locations/global/keyRings/your-ring/cryptoKeys/your-key",
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	// Call the API.
	result, err := kmsClient.Decrypt(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %v\n", err)
	}

	// Optional, but recommended: perform integrity verification on result.
	// For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
	// https://cloud.google.com/kms/docs/data-integrity-guidelines
	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("Decrypt: response corrupted in-transit")
	}

	fmt.Printf("Decrypted plaintext: %s\n", result.Plaintext)
	return result.Plaintext, nil
}

func generateKey(id string) *datastore.Key {
	key := datastore.NameKey("Token", id, nil)
	key.Namespace = "stage"
	return key
}
