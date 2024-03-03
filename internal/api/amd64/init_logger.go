package amd64

/*
#include "bindings.h"
*/
import "C"

func InitLogger() {
	C.init_logger()
}
