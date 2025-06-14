package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestCapsuleSkipping(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	var buf bytes.Buffer
	require.NoError(t, http3.WriteCapsule(&buf, 1337, []byte("foo")))
	require.NoError(t, http3.WriteCapsule(&buf, 42, []byte("bar")))
	require.ErrorIs(t, skipCapsules(&buf), io.EOF)
}

func TestReadDeadline(t *testing.T) {
	setupStreamAndConn := func() (*MockStream, *proxiedConn) {
		str := NewMockStream(gomock.NewController(t))
		done := make(chan struct{})
		t.Cleanup(func() {
			str.EXPECT().Close().MaxTimes(1)
			close(done)
		})
		str.EXPECT().Read(gomock.Any()).DoAndReturn(func([]byte) (int, error) {
			<-done
			return 0, errors.New("test done")
		}).MaxTimes(1)
		return str, newProxiedConn(str, nil)
	}

	t.Run("read after deadline", func(t *testing.T) {
		str, conn := setupStreamAndConn()
		str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(-time.Second)))
		_, _, err := conn.ReadFrom(make([]byte, 100))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})

	t.Run("unblocking read", func(t *testing.T) {
		str, conn := setupStreamAndConn()
		str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}).Times(2)
		errChan := make(chan error, 1)
		go func() {
			_, _, err := conn.ReadFrom(make([]byte, 100))
			errChan <- err
		}()
		select {
		case err := <-errChan:
			t.Fatalf("didn't expect ReadFrom to return early: %v", err)
		case <-time.After(scaleDuration(50 * time.Millisecond)):
		}
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(-time.Second)))
		select {
		case err := <-errChan:
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		case <-time.After(scaleDuration(100 * time.Millisecond)):
			t.Fatal("timeout")
		}
		_, _, err := conn.ReadFrom(make([]byte, 100))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	})

	t.Run("extending the deadline", func(t *testing.T) {
		str, conn := setupStreamAndConn()
		str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}).MaxTimes(2) // might be called a 2nd time depending on when the cancellation Go routine does its job

		start := time.Now()
		d := scaleDuration(75 * time.Millisecond)
		require.NoError(t, conn.SetReadDeadline(start.Add(d)))
		errChan := make(chan error, 1)
		go func() {
			_, _, err := conn.ReadFrom(make([]byte, 100))
			errChan <- err
		}()
		require.NoError(t, conn.SetReadDeadline(start.Add(2*d)))
		select {
		case err := <-errChan:
			if since := time.Since(start); since < 2*d {
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
				t.Fatalf("ReadFrom returned early: %s, expected >= %s", since, 2*d)
			}
		case <-time.After(10 * d):
			t.Fatal("timeout")
		}
	})

	t.Run("cancelling the deadline", func(t *testing.T) {
		str, conn := setupStreamAndConn()
		str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})

		start := time.Now()
		d := scaleDuration(75 * time.Millisecond)
		require.NoError(t, conn.SetReadDeadline(start.Add(d)))
		errChan := make(chan error, 1)
		go func() {
			_, _, err := conn.ReadFrom(make([]byte, 100))
			errChan <- err
		}()
		require.NoError(t, conn.SetReadDeadline(time.Time{}))
		select {
		case <-errChan:
			t.Fatal("deadline was cancelled")
		case <-time.After(2 * d):
		}

		// test shutdown
		require.NoError(t, conn.SetReadDeadline(time.Now()))
		select {
		case err := <-errChan:
			require.Error(t, err)
		case <-time.After(scaleDuration(100 * time.Millisecond)):
			t.Fatal("timeout")
		}
	})

	t.Run("multiple deadlines", func(t *testing.T) {
		str, conn := setupStreamAndConn()
		const num = 10
		const maxDeadline = 5 * time.Millisecond
		str.EXPECT().ReceiveDatagram(gomock.Any()).DoAndReturn(func(ctx context.Context) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}).MinTimes(num)

		for range num {
			// random duration between -5ms and 5ms
			d := scaleDuration(maxDeadline - time.Duration(rand.Int64N(2*maxDeadline.Nanoseconds())))
			t.Logf("setting deadline to %v", d)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(d)))
			_, _, err := conn.ReadFrom(make([]byte, 100))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		}
	})
}
