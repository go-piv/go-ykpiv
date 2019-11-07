// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2017
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. }}}

package main

import (
	"fmt"

	"pault.ag/go/ykpiv"
)

func ohshit(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	readers, err := ykpiv.Readers()
	ohshit(err)

	for _, reader := range readers {
		fmt.Printf("Reader:  %s\n", reader)
		token, err := ykpiv.New(ykpiv.Options{
			Reader: reader,
		})
		ohshit(err)
		defer token.Close()
		version, err := token.Version()
		ohshit(err)
		fmt.Printf("Version: %s\n", version)
		serial, err := token.Serial()
		ohshit(err)
		fmt.Printf("Serial:  %d\n", serial)

		for _, slotId := range []ykpiv.SlotId{
			ykpiv.Authentication,
			ykpiv.Signature,
			ykpiv.CardAuthentication,
			ykpiv.KeyManagement,
		} {
			slot, err := token.Slot(slotId)
			if err != nil {
				continue
			}
			fmt.Printf("Slot %s: %s\n", slotId, slot.Certificate.Subject.CommonName)
		}
		fmt.Printf("\n")
	}

}

// vim: foldmethod=marker
