package amd64

/*
#include "bindings.h"
*/
import "C"

func InitLogger() error {
	C.init_logger()
	return nil
}
