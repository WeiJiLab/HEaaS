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
	logger     *glog.Logger

	keypairMap     map[string]*KeyPair
	keypairHashMap map[[sha256.Size]byte]*KeyPair
)

type fheServer struct {
	pb.UnimplementedFHEServer

	kgen bfv.KeyGenerator
}

type KeyPair struct {
	PublicKey bfv.PublicKey
	SecretKey bfv.SecretKey
}

// GenerateKey returns a fhe key pair
func (s *fheServer) GenerateKey(ctx context.Context, _ *empty.Empty) (*pb.KeyPair, error) {
	logger.Info("GenerateKey: generating")
	sk, pk := s.kgen.GenKeyPair()
	logger.Info("GenerateKey: done")
	return marshalKeyPair(KeyPair{PublicKey: *pk, SecretKey: *sk})
}

// StoreKey store a fhe key pair
func (s *fheServer) StoreKey(ctx context.Context, req *pb.StoreKeyRequest) (*empty.Empty, error) {
	logger.Infof("StoreKey: store key: %s", req.Key)
	kp, err := unmarshalKeyPair(*req.KeyPair)
	if err != nil {
		return &empty.Empty{}, err
	}
	keypairMap[req.Key] = &kp
	pk_sha256 := sha256.Sum256(req.KeyPair.PublicKey)
	keypairHashMap[pk_sha256] = &kp
	return &empty.Empty{}, nil
}

// FetchPublicKey fetch a fhe key pair with only Public key
func (s *fheServer) FetchPublicKey(ctx context.Context, req *pb.FetchPublicKeyRequest) (*pb.KeyPair, error) {
	logger.Infof("FetchPublicKey: fetching key: %s", req.Key)
	kp, err := marshalKeyPair(*keypairMap[req.Key])
	kp.SecretKey = []byte{}
	return kp, err
}

// FetchPublicKeyBySHA256 fetch a fhe key pair with only Public key
func (s *fheServer) FetchPublicKeyBySHA256(ctx context.Context, req *pb.FetchPublicKeyRequest) (*pb.KeyPair, error) {
	key, err := hex.DecodeString(req.Key)
	if err != nil {
		logger.Errorf("failed to unmarshallKeyPair secretKey: %v", err)
		return &pb.KeyPair{}, err
	}
	logger.Infof("FetchPublicKeyBySHA256: fetching key: %s", req.Key)
	var hash [sha256.Size]byte
	copy(hash[:], key)
	kp, err := marshalKeyPair(*keypairHashMap[hash])
	kp.SecretKey = []byte{}
	return kp, err
}

func unmarshalKeyPair(kp pb.KeyPair) (KeyPair, error) {
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

func marshalKeyPair(kp KeyPair) (*pb.KeyPair, error) {
	sk := kp.SecretKey
	sk_bytes, err := sk.MarshalBinary()
	if err != nil {
		logger.Errorf("failed to marshallKeyPair secretKey: %v", err)
		return &pb.KeyPair{}, err
	}
	pk := kp.PublicKey
	pk_bytes, err := pk.MarshalBinary()
	if err != nil {
		logger.Errorf("failed to marshallKeyPair publicKey: %v", err)
		return &pb.KeyPair{}, err
	}
	logger.Info("GenerateKey: done")
	return &pb.KeyPair{PublicKey: pk_bytes, SecretKey: sk_bytes}, nil
}

func newServer() *fheServer {
	// BFV parameters (128 bit security)
	params := bfv.DefaultParams[bfv.PN13QP218]
	// Plaintext modulus
	params.T = 0x3ee0001

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
