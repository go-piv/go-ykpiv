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
	"os"

	"github.com/urfave/cli"

	"pault.ag/go/ykpiv"
)

func main() {
	app := cli.NewApp()
	app.Name = "ykpiv"
	app.Usage = "Tools to talk with your Yubikey"

	app.Flags = []cli.Flag{}

	app.Commands = []cli.Command{
		cli.Command{
			Name: "ls",
			Action: func(c *cli.Context) error {
				return Ls(c)
			},
			Flags: []cli.Flag{},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

func Ls(c *cli.Context) error {
	readers, err := ykpiv.Readers()
	if err != nil {
		return err
	}

	for _, reader := range readers {
		yubikey, err := ykpiv.New(ykpiv.Options{Reader: reader})
		if err != nil {
			return err
		}
		defer yubikey.Close()

		version, err := yubikey.Version()
		if err != nil {
			return err
		}

		retries, err := yubikey.PINRetries()
		if err != nil {
			return err
		}

		fmt.Printf("PIV Version %s - %s\n", version, reader)
		fmt.Printf("  PIN Retries: %d\n", retries)

		for _, slotId := range []ykpiv.SlotId{
			ykpiv.Authentication,
			ykpiv.Signature,
			ykpiv.KeyManagement,
			ykpiv.CardAuthentication,
		} {
			slot, err := yubikey.Slot(slotId)
			if ykpiv.GenericError.Equal(err) {
				continue
			} else if err != nil {
				return err
			}

			fmt.Printf(
				"  %s Certificate:\n    CN=%s\n    Serial=%X\n",
				slotId.Name,
				slot.Certificate.Subject.CommonName,
				slot.Certificate.SerialNumber,
			)
		}
	}

	return nil
}

// vim: foldmethod=marker
