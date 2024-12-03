package masque

// A Tracer can be used to monitor the progress of a proxied connection.
type Tracer struct {
	// SentData is called when data is sent towards the target.
	SentData func(n int)
	// SentDirectionClosed is called when the send direction (towards the target) is closed.
	SendDirectionClosed func()
	// ReceivedData is called when data is received from the target.
	ReceivedData func(n int)
	// ReceiveDirectionClosed is called when the receive direction (from the target) is closed.
	ReceiveDirectionClosed func()
}
