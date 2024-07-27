package mdktools

import "fmt"

type MdkErrorCode int

type MdkError struct {
	major MdkErrorCode
	sub   int
	msg   string
}

func NewMdkError(code MdkErrorCode, sub int, msg string, v ...[]string) *MdkError {
	return &MdkError{major: code, sub: sub, msg: fmt.Sprintf(msg, v)}
}

func NewMdkErrorWrap(code MdkErrorCode, sub int, outer error) *MdkError {
	return &MdkError{major: code, sub: sub, msg: outer.Error()}
}

func (e *MdkError) Error() string {
	return fmt.Sprintf("Error: %s, %X;%X", e.msg, e.major, e.sub)
}

func (e *MdkError) Code() MdkErrorCode {
	return e.major
}
func (e *MdkError) Sub() int {
	return e.sub
}

const (
	UNKNOWN_ERROR      MdkErrorCode = iota
	INVALID_DATA       MdkErrorCode = iota
	SIGNATURE_ERROR    MdkErrorCode = iota
	CERTIFICATE_ERROR  MdkErrorCode = iota
	INCORRECT_PASSWORD MdkErrorCode = iota
)
