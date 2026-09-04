package mapper

import (
	"github.com/Weit145/auth-startup/internal/domain"
	pb "github.com/weit145/proto-startup/auth"
)

func MapDomainToConfirmResponse(accessToken domain.AccessToken) *pb.ConfirmResponse {
	return &pb.ConfirmResponse{
		AccessToken: accessToken.Value(),
	}
}

func MapDomainToAuthResponse(user domain.User, tokens domain.Tokens) *pb.AuthResponse {
	return &pb.AuthResponse{
		User: &pb.User{
			Id:    user.ID().String(),
			Email: user.Email(),
			Role:  user.Role(),
		},
		AccessToken:  tokens.AccessToken().Value(),
		RefreshToken: tokens.RefreshToken().Value(),
	}
}
