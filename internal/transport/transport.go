package transport

type Transport interface {
	Connect() error
	Send(data []byte) error
	Close() error
}
