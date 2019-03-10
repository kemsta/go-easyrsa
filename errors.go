package easyrsa

type NotExist struct {
	message string
}

func (e *NotExist) Error() string {
	return e.message
}

func NewNotExist(message string) *NotExist {
	return &NotExist{message: message}
}
