//go:build gomock || generate

package masque

//go:generate sh -c "go run go.uber.org/mock/mockgen -typed -build_flags=\"-tags=gomock\" -package masque_test -self_package github.com/quic-go/masque-go -destination mock_stream_test.go github.com/quic-go/quic-go/http3 Stream && cat mock_stream_test.go | sed s@protocol\\.StreamID@quic.StreamID@g | sed s@qerr\\.StreamErrorCode@quic.StreamErrorCode@g > tmp.go && mv tmp.go mock_stream_test.go && go run golang.org/x/tools/cmd/goimports -w mock_stream_test.go"
