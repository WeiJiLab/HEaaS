package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	glog "github.com/google/logger"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/LabZion/HEaaS/common"
	pb "github.com/LabZion/HEaaS/fhe"
	"github.com/ldsec/lattigo/bfv"
)

var (
	tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	logFile    = flag.String("log_file", "./HEaaS.log", "The Logging file")
	certFile   = flag.String("cert_file", "", "The TLS cert file")
	keyFile    = flag.String("key_file", "", "The TLS key file")
	jsonDBFile = flag.String("json_db_file", "", "A json file containing a list of features")
	port       = flag.Int("port", 10000, "The server port")

	params *bfv.Parameters
	logger *glog.Logger

	keypairMap     map[string]*KeyPair
	keypairHashMap map[[sha256.Size]byte]*KeyPair

	bidMap map[string](map[string]*Bid)
	askMap map[string]*Ask
)

type fheServer struct {
	pb.UnimplementedFHEServer

	kgen bfv.KeyGenerator
}

// Ask is an ask with limit price and credit
type Ask struct {
	account string

	limitPrice *bfv.Ciphertext
}

// Bid is an ask with limit price and credit
type Bid struct {
	account string

	limitPrice *bfv.Ciphertext
	credit     *bfv.Ciphertext
}

// KeyPair is a bfv key pair
type KeyPair struct {
	PublicKey bfv.PublicKey
	SecretKey bfv.SecretKey
}

// GenerateKey returns a fhe key pair
func (s *fheServer) GenerateKey(ctx context.Context, _ *empty.Empty) (*pb.KeyPair, error) {
	logger.Info("GenerateKey: generating")
	sk, pk := s.kgen.GenKeyPair()
	logger.Info("GenerateKey: done")
	return marshalKeyPair(&KeyPair{PublicKey: *pk, SecretKey: *sk})
}

// StoreKey store a fhe key pair
func (s *fheServer) StoreKey(ctx context.Context, req *pb.StoreKeyRequest) (*empty.Empty, error) {
	logger.Infof("StoreKey: store key account: %s", req.Account)
	kp, err := unmarshalKeyPair(req.KeyPair)
	if err != nil {
		return &empty.Empty{}, err
	}
	keypairMap[req.Account] = &kp
	pkSHA256 := sha256.Sum256(req.KeyPair.PublicKey)
	keypairHashMap[pkSHA256] = &kp
	return &empty.Empty{}, nil
}

// StorePublicKey store a fhe key pair
func (s *fheServer) StorePublicKey(ctx context.Context, req *pb.StoreKeyRequest) (*empty.Empty, error) {
	logger.Infof("StoreKey: store key account: %s", req.Account)
	kp, err := unmarshalKeyPairPublic(req.KeyPair)
	if err != nil {
		return &empty.Empty{}, err
	}
	keypairMap[req.Account] = &kp
	pkSHA256 := sha256.Sum256(req.KeyPair.PublicKey)
	keypairHashMap[pkSHA256] = &kp
	return &empty.Empty{}, nil
}

// FetchPublicKey fetch a fhe key pair with only Public key
func (s *fheServer) FetchPublicKey(ctx context.Context, req *pb.FetchPublicKeyRequest) (*pb.KeyPair, error) {
	logger.Infof("FetchPublicKey: fetching key account: %s", req.Account)
	keypair, ok := keypairMap[req.Account]
	if !ok {
		logger.Errorf("FetchPublicKey: key account %s not found", req.Account)
		return nil, fmt.Errorf("key by account %s not found", req.Account)
	}
	kp, err := marshalKeyPairPublic(keypair)
	kp.SecretKey = []byte{}
	return kp, err
}

// FetchPublicKeyBySHA256 fetch a fhe key pair with only Public key
func (s *fheServer) FetchPublicKeyBySHA256(ctx context.Context, req *pb.FetchPublicKeyBySHA256Request) (*pb.KeyPair, error) {
	logger.Infof("FetchPublicKeyBySHA256: fetching key: %s", req.Hash)
	key, err := hex.DecodeString(req.Hash)
	if err != nil {
		logger.Errorf("failed to unmarshallKeyPair secretKey: %v", err)
		return &pb.KeyPair{}, err
	}
	logger.Infof("FetchPublicKeyBySHA256: fetching key: %s", req.Hash)
	var hash [sha256.Size]byte
	copy(hash[:], key)
	keypair, ok := keypairHashMap[hash]
	if !ok {
		logger.Errorf("FetchPublicKeyBySHA256: hash key %s not found", hash)
		return nil, fmt.Errorf("key by hash %s not found", hash)
	}
	kp, err := marshalKeyPairPublic(keypair)
	kp.SecretKey = []byte{}
	return kp, err
}

// SetAsk
func (s *fheServer) SetAsk(ctx context.Context, req *pb.AskRequest) (*empty.Empty, error) {
	logger.Infof("Recieve Ask: store ask account: %s", req.Account)

	limitPrice := &bfv.Ciphertext{}
	if err := limitPrice.UnmarshalBinary(req.LimitPriceCipherText); err != nil {
		logger.Errorf("limitPrice.UnmarshalBinary(req.LimitPriceCipherText); err: %s", err)
		return &empty.Empty{}, err
	}

	askMap[req.Account] = &Ask{
		account:    req.Account,
		limitPrice: limitPrice,
	}
	bidMap[req.Account] = make(map[string]*Bid)
	return &empty.Empty{}, nil
}

// SetBid
func (s *fheServer) SetBid(ctx context.Context, req *pb.BidRequest) (*empty.Empty, error) {
	logger.Infof("Recieve Bid: store bid targetAccount: %s, account: %s", req.TargetAccount, req.Account)

	limitPrice := bfv.NewCiphertext(params, 0)
	if err := limitPrice.UnmarshalBinary(req.LimitPriceCipherText); err != nil {
		logger.Errorf("limit.UnmarshalBinary(req.LimitPriceCipherText); err: %s", err)
		return &empty.Empty{}, err
	}

	credit := bfv.NewCiphertext(params, 0)
	if err := credit.UnmarshalBinary(req.CreditCipherText); err != nil {
		logger.Errorf("credit.UnmarshalBinary(req.CreditCipherText); err: %s", err)
		return &empty.Empty{}, err
	}

	bidMap[req.TargetAccount][req.Account] = &Bid{
		account:    req.Account,
		limitPrice: limitPrice,
		credit:     credit,
	}
	return &empty.Empty{}, nil
}

// EligibleBid
func (s *fheServer) EligibleBid(ctx context.Context, req *pb.EligibleBidRequest) (*pb.EligibleBidResponse, error) {
	logger.Infof("Recieve EligibleBid: store ask account: %s", req.Account)

	kp, ok := keypairMap[req.Account]
	if !ok {
		logger.Errorf("kp: keypair by account %s not found", req.Account)
		return nil, fmt.Errorf("keypairMap: keypair by account %s not found", req.Account)
	}
	encryptorPk := bfv.NewEncryptorFromPk(common.GetParams(), &kp.PublicKey)

	ask, ok := askMap[req.Account]
	if !ok {
		logger.Errorf("askMap: ask by account %s not found", req.Account)
		return nil, fmt.Errorf("askMap: ask by account %s not found", req.Account)
	}

	bidMap, ok := bidMap[req.Account]
	if !ok {
		logger.Errorf("bidMap: bid by targetAccount %s not found", req.Account)
		return nil, fmt.Errorf("bidMap: bid by targetAccount %s not found", req.Account)
	}

	evaluator := bfv.NewEvaluator(common.GetParams())
	bids := []*pb.EligibleBidResponse_Bid{}

	for key, bid := range bidMap {
		logger.Infof("Account: %s => Bid: %s", key, bid)
		limitPriceDistanceCiphertext, _ := evaluator.SubNew(ask.limitPrice, bid.limitPrice).MarshalBinary()

		//TODO: credit should be provided by server's Database
		credit := common.EncryptIntCiphertext(encryptorPk, 630)

		creditDistanceCiphertext, _ := evaluator.SubNew(credit, bid.credit).MarshalBinary()
		bids = append(bids, &pb.EligibleBidResponse_Bid{
			Account:                      key,
			LimitPriceDistanceCiphertext: limitPriceDistanceCiphertext,
			CreditDistanceCiphertext:     creditDistanceCiphertext,
		})
	}

	logger.Infof("Ask: %v", ask)
	logger.Infof("BidMap: %v", bidMap)
	return &pb.EligibleBidResponse{
		TotalBidNumber: uint64(len(bidMap)),
		Bids:           bids,
	}, nil
}

func unmarshalKeyPairPublic(kp *pb.KeyPair) (KeyPair, error) {
	pk := bfv.PublicKey{}
	var err error
	err = pk.UnmarshalBinary(kp.PublicKey)
	if err != nil {
		logger.Errorf("failed to unmarshallKeyPair publicKey: %v", err)
		return KeyPair{}, err
	}
	return KeyPair{
		PublicKey: pk,
	}, nil
}

func unmarshalKeyPair(kp *pb.KeyPair) (KeyPair, error) {
	sk := bfv.SecretKey{}
	pk := bfv.PublicKey{}
	var err error
	err = sk.UnmarshalBinary(kp.SecretKey)
	if err != nil {
		logger.Errorf("failed to unmarshallKeyPair secretKey: %v", err)
		return KeyPair{}, err
	}
	err = pk.UnmarshalBinary(kp.PublicKey)
	if err != nil {
		logger.Errorf("failed to unmarshallKeyPair publicKey: %v", err)
		return KeyPair{}, err
	}
	return KeyPair{
		PublicKey: pk,
		SecretKey: sk,
	}, nil
}

func marshalKeyPairPublic(kp *KeyPair) (*pb.KeyPair, error) {
	pk := kp.PublicKey
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		logger.Errorf("failed to marshallKeyPair publicKey: %v", err)
		return &pb.KeyPair{}, err
	}
	return &pb.KeyPair{PublicKey: pkBytes}, nil
}

func marshalKeyPair(kp *KeyPair) (*pb.KeyPair, error) {
	sk := kp.SecretKey
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		logger.Errorf("failed to marshallKeyPair secretKey: %v", err)
		return &pb.KeyPair{}, err
	}
	pk := kp.PublicKey
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		logger.Errorf("failed to marshallKeyPair publicKey: %v", err)
		return &pb.KeyPair{}, err
	}
	return &pb.KeyPair{PublicKey: pkBytes, SecretKey: skBytes}, nil
}

func newServer() *fheServer {
	params = common.GetParams()
	fmt.Println("============================================")
	fmt.Println("Homomorphic computations on batched integers")
	fmt.Println("============================================")
	fmt.Println()
	fmt.Printf("Parameters : N=%d, T=%d, Q = %d bits, sigma = %f \n",
		1<<params.LogN, params.T, params.LogQP(), params.Sigma)
	fmt.Println()

	kgen := bfv.NewKeyGenerator(params)

	keypairMap = make(map[string]*KeyPair)
	keypairHashMap = make(map[[sha256.Size]byte]*KeyPair)

	askMap = make(map[string]*Ask)
	bidMap = make(map[string](map[string]*Bid))

	s := &fheServer{kgen: kgen}
	return s
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		if *certFile == "" {
			*certFile = testdata.Path("server1.pem")
		}
		if *keyFile == "" {
			*keyFile = testdata.Path("server1.key")
		}
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	lf, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer lf.Close()
	logger = glog.Init("HEaaS", true, false, ioutil.Discard)

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterFHEServer(grpcServer, newServer())

	logger.Infof("HEaaS Serve on Port %s", fmt.Sprintf("localhost:%d", *port))
	grpcServer.Serve(lis)
}
