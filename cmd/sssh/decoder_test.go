package main

import (
	"bytes"
	"fmt"
	"log"
	"testing"
)

func TestDecoder_Write(t *testing.T) {
	str := []byte{0xc7, 0xe0, 0xe3, 0xf0, 0xf3, 0xe7, 0xea, 0xe0}
	var b bytes.Buffer
	d := newWindowsDecoder(&b)
	fmt.Fprint(d, string(str))
	if b.String() != "Загрузка" {
		log.Fatal("Invalid decoding: ", b.String())
	}
}
