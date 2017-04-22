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
	"io"
	"os"

	"crypto/tls"
	"net/http"

	"github.com/urfave/cli"

	"pault.ag/go/ykpiv"
)

func main() {
	app := cli.NewApp()
	app.Name = "ykget"
	app.Usage = "GET an HTTP resource with your Yubikey"

	var PIN string = ""
	var reader string = ""

	var slotId string = ""

	var yubikey *ykpiv.Yubikey
	var slot *ykpiv.Slot

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "pin",
			Usage:       "PIN for the Yubikey",
			Value:       "",
			Destination: &PIN,
			EnvVar:      "YKPIV_PIN",
		},

		cli.StringFlag{
			Name:        "slot",
			Usage:       "Slot to use ('authentication', 'signature')",
			Value:       "authentication",
			Destination: &slotId,
			EnvVar:      "YKPIV_SLOT",
		},

		cli.StringFlag{
			Name:        "reader",
			Usage:       "Reader to connect to",
			Value:       "Yubikey",
			Destination: &reader,
			EnvVar:      "YKPIV_READER",
		},
	}

	app.After = func(c *cli.Context) error {
		if yubikey != nil {
			return yubikey.Close()
		}
		return nil
	}

	app.Before = func(c *cli.Context) error {
		var err error
		yubikey, err = ykpiv.New(ykpiv.Options{
			Reader: reader,
		})
		if err != nil {
			return err
		}
		if PIN != "" {
			if err := yubikey.Login(PIN); err != nil {
				return err
			}
		}

		switch slotId {
		case "authentication":
			slot, err = yubikey.Authentication()
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("Unknown slot: %s", slotId)
		}

		return nil
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name: "get",
			Action: func(c *cli.Context) error {
				return Get(*slot, c)
			},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "url",
					Value: "https://certlint.paultag.house:443/",
					Usage: "URL to GET",
				},
			},
		},
	}

	app.Run(os.Args)
}

func Get(slot ykpiv.Slot, c *cli.Context) error {
	tlsCert, err := slot.TLSCertificate()
	if err != nil {
		return err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{*tlsCert}},
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://certlint.paultag.house:443")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

// vim: foldmethod=marker
