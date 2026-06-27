package transport

type Transport interface {
	Connect() error
	Send(data []byte) ([]byte, error)
	Close() error
}
