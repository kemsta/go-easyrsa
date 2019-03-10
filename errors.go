package easyrsa

type NotExist struct {
	err string
}

func (e *NotExist) Error() string {
	return e.err
}

func NewNotExist(err string) *NotExist {
	return &NotExist{err: err}
}
