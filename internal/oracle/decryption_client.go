package oracle

import (
	"context"
	"log"
	"time"

	pb "github.com/fhenixprotocol/decryption-oracle-proto/go/oracle"
	"google.golang.org/grpc"
)

const (
	grpcTimeout = 10 * time.Second
)

// DecryptionNetworkClient defines the interface for our client
type DecryptionNetworkClient interface {
	Decrypt(*pb.FheEncrypted) (string, string, error)
	Reencrypt(*pb.FheEncrypted, string) (string, string, error)
	AssertIsNil(*pb.FheEncrypted) (bool, string, error)
	Close()
}

// GrpcDecryptionNetworkClient is the real implementation
type GrpcDecryptionNetworkClient struct {
	conn   *grpc.ClientConn
	client pb.DecryptionOracleClient
}

// New creates a new GrpcDecryptionNetworkClient
func NewDecryptionNetworkClient(address string) DecryptionNetworkClient {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}

	client := pb.NewDecryptionOracleClient(conn)
	return &GrpcDecryptionNetworkClient{
		conn:   conn,
		client: client,
	}
}

// AssertIsNil wraps around the gRPC AssertIsNil call
func (g *GrpcDecryptionNetworkClient) AssertIsNil(encrypted *pb.FheEncrypted) (result bool, signature string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	r, err := g.client.AssertIsNil(ctx, &pb.IsNilRequest{Encrypted: encrypted})
	if err != nil {
		return false, "", err
	}

	return r.IsNil, r.GetSignature(), nil
}

// Decrypt wraps around the gRPC Decrypt call
func (g *GrpcDecryptionNetworkClient) Decrypt(encrypted *pb.FheEncrypted) (decrypted string, signature string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	r, err := g.client.Decrypt(ctx, &pb.DecryptRequest{Encrypted: encrypted})
	if err != nil {
		return "", "", err
	}

	return r.GetDecrypted(), r.GetSignature(), nil
}

// Reencrypt wraps around the gRPC Reencrypt call
func (g *GrpcDecryptionNetworkClient) Reencrypt(encrypted *pb.FheEncrypted, userPublicKey string) (decrypted string, signature string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), grpcTimeout)
	defer cancel()

	r, err := g.client.Reencrypt(ctx, &pb.ReencryptRequest{
		Encrypted:     encrypted,
		UserPublicKey: userPublicKey,
	})
	if err != nil {
		return "", "", err
	}

	return r.GetReencrypted(), r.GetSignature(), nil
}

// Close the gRPC connection when done
func (g *GrpcDecryptionNetworkClient) Close() {
	// todo: handle errors
	_ = g.conn.Close()
}
