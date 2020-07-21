package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/LabZion/HEaaS/common"
	pb "github.com/LabZion/HEaaS/fhe"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/ldsec/lattigo/bfv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"
)

var (
	tls                = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	caFile             = flag.String("ca_file", "", "The file containing the CA root cert file")
	serverAddr         = flag.String("server_addr", "localhost:10000", "The server address in the format of host:port")
	serverHostOverride = flag.String("server_host_override", "x.test.youtube.com", "The server name used to verify the hostname returned by the TLS handshake")
)

// KeyPair is a pair of bfv public and private keys
type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

// Bid is a bid
type Bid struct {
	LimitPriceDistance int
	CreditDistance     int
}

// generateKeysRemote gets a new pair of fhe keys
func generateKeysRemote(client pb.FHEClient) KeyPair {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keyPair, err := client.GenerateKey(ctx, &empty.Empty{})
	if err != nil {
		log.Fatalf("%v.GenerateKey(_) = _, %v: ", client, err)
	}
	return KeyPair{
		PublicKey: keyPair.PublicKey,
		SecretKey: keyPair.SecretKey,
	}
}

// storeKey store a pair of fhe keys
func storeKey(client pb.FHEClient, account string, keyPair KeyPair) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := client.StoreKey(ctx, &pb.StoreKeyRequest{
		Account: account,
		KeyPair: &pb.KeyPair{
			PublicKey: keyPair.PublicKey,
			SecretKey: keyPair.SecretKey,
		},
	})
	if err != nil {
		log.Fatalf("%v.StoreKey(_) = _, %v: ", client, err)
	}
	return
}

// storePublicKey store a pair of fhe keys
func storePublicKey(client pb.FHEClient, account string, keyPair KeyPair) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := client.StorePublicKey(ctx, &pb.StoreKeyRequest{
		Account: account,
		KeyPair: &pb.KeyPair{
			PublicKey: keyPair.PublicKey,
		},
	})
	if err != nil {
		log.Fatalf("%v.StoreKey(_) = _, %v: ", client, err)
	}
	return
}

// fetchPublicKey store a pair of fhe keys
func fetchPublicKey(client pb.FHEClient, account string) KeyPair {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keyPair, err := client.FetchPublicKey(ctx, &pb.FetchPublicKeyRequest{
		Account: account,
	})
	if err != nil {
		log.Fatalf("%v.FetchPublicKey(_) = _, %v: ", client, err)
	}
	return KeyPair{
		PublicKey: keyPair.PublicKey,
		SecretKey: keyPair.SecretKey,
	}
}

// setAsk set an ask for account
func setAsk(client pb.FHEClient, keyPair KeyPair, account string, limit int) {
	params := common.GetParams()

	sk := bfv.SecretKey{}
	sk.UnmarshalBinary(keyPair.SecretKey)
	encryptorSk := bfv.NewEncryptorFromSk(params, &sk)

	limitCiphertextBytes := common.EncryptInt(encryptorSk, limit)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := client.SetAsk(ctx, &pb.AskRequest{
		Account:              account,
		LimitPriceCipherText: limitCiphertextBytes,
	})
	if err != nil {
		log.Fatalf("%v.SetAsk(_) = _, %v: ", client, err)
	}
	return
}

// fetchPublicKeyBySHA256 store a pair of fhe keys
func fetchPublicKeyBySHA256(client pb.FHEClient, hash string) KeyPair {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keyPair, err := client.FetchPublicKeyBySHA256(ctx, &pb.FetchPublicKeyBySHA256Request{
		Hash: hash,
	})
	if err != nil {
		log.Fatalf("%v.FetchPublicKeyBySHA256(_) = _, %v: ", client, err)
	}
	return KeyPair{
		PublicKey: keyPair.PublicKey,
		SecretKey: keyPair.SecretKey,
	}
}

// getEligibleBids fetch all eligible bids
func getEligibleBids(client pb.FHEClient, keyPair KeyPair, account string) (uint64, []Bid) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eligibleBidResponse, err := client.EligibleBid(ctx, &pb.EligibleBidRequest{
		Account: account,
	})
	if err != nil {
		log.Fatalf("%v.EligibleBid(_) = _, %v: ", client, err)
	}
	// Decrypting Bids
	bids := []Bid{}
	params := common.GetParams()

	sk := bfv.SecretKey{}
	sk.UnmarshalBinary(keyPair.SecretKey)
	decryptor := bfv.NewDecryptor(params, &sk)

	for _, bid := range eligibleBidResponse.Bids {
		limitPriceDistance := common.DecryptInt(decryptor, bid.LimitPriceDistanceCiphertext)
		creditDistance := common.DecryptInt(decryptor, bid.CreditDistanceCiphertext)

		bids = append(bids, Bid{
			LimitPriceDistance: limitPriceDistance,
			CreditDistance:     creditDistance,
		})
	}
	return eligibleBidResponse.TotalBidNumber, bids
}

func main() {
	flag.Parse()
	var opts []grpc.DialOption
	if *tls {
		if *caFile == "" {
			*caFile = testdata.Path("ca.pem")
		}
		creds, err := credentials.NewClientTLSFromFile(*caFile, *serverHostOverride)
		if err != nil {
			log.Fatalf("Failed to create TLS credentials %v", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	opts = append(opts, grpc.WithBlock())
	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewFHEClient(conn)

	kp := generateKeysRemote(client)
	storePublicKey(client, "fan@torchz.net", kp)
	/* test fetch key is in third party client

	keyPair := fetchPublicKey(client, "fan@torchz.net")
	pkSHA256 := sha256.Sum256(keyPair.PublicKey)

	log.Printf("public key sha256: %x", pkSHA256)

	keyPairBySHA256 := fetchPublicKeyBySHA256(client, hex.EncodeToString(pkSHA256[:]))

	// check key manager secret key should be empty
	if len(keyPair.SecretKey) != 0 {
		log.Fatalf("length of keyPair.SecretKey != 0, %d", len(keyPair.SecretKey))
	}
	// check key manager public key should finde same key via hash and account
	if !bytes.Equal(keyPair.PublicKey, keyPairBySHA256.PublicKey) {
		log.Fatalf("keyPair.PublicKey != keyPairBySHA256.PublicKey")
	}
	*/

	reader := bufio.NewReader(os.Stdin)

	limit := 100
	fmt.Println("Saving Ask.")
	setAsk(client, kp, "fan@torchz.net", limit)

	fmt.Println("Collecting Bids. Press <Enter> to close and getEligibleBids:")
	reader.ReadString('\n')

	number, bids := getEligibleBids(client, kp, "fan@torchz.net")

	fmt.Printf("total bid number: %d\n", number)
	fmt.Printf("bids: %#v\n", bids)
}
