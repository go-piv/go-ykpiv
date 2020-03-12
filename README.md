go-ykpiv
========

go-ykpiv is a high level cgo wrapper around `libykpiv.so.1` that implements an
idiomatic go API fit for use when applications need to communicate with a
Yubikey in PIV mode.

What's PIV?
-----------

PIV Cards are cards defined by FIPS 201, a Federal US Government standard
defining the ID cards employees use. At its core, it's a set of x509
Certificates and corresponding private keys in a configuration that is
standardized across implementations.

For more details on how PIV Tokens can be used, the FICAM
(Federal Identity, Credential, and Access Management) team at GSA
(General Services Administration) has published some guides on GitHub
under [GSA/piv-guides](https://github.com/GSA/piv-guides)

How is this different than OpenSC?
----------------------------------

Most PIV tokens, Yubikeys included, can be used as a PKCS#11 device using
[OpenSC](https://github.com/opensc/opensc), and Yubikeys are even capable of doing
Signing and Decryption through that interface. However, some management functions
are not exposed in the PKCS#11 OpenSC interface, so this library may be of use
when one wants to write a new Certificate, or set PINs.

Development
===========

Testing
-------

To run the tests, you'll need to find a Yubikey that you're willing to wipe
clean, and destroy all data on it. After you've found such a key, remove all
other Yubikeys from your machine.

The tests will panic if the `YKPIV_YES_DESTROY_MY_KEY` environment variable
is unset.

Running the tests will **reset** your Yubikey a few times (once per test), and
you will wind up with a key with the default PIN, PUK and Management Key.

Installation
============

Debian
------

```
sudo apt install build-essential libykpiv-dev
go get pault.ag/go/ykpiv
```

MacOS X
------

```
brew install yubico-piv-tool
go get pault.ag/go/ykpiv
```

Examples
========

```go
package main

import (
	"fmt"

	"pault.ag/go/ykpiv"
)

func main() {
	yubikey, err := ykpiv.New(ykpiv.Options{
		// Verbose: true,
		Reader: "Yubico Yubikey NEO U2F+CCID 01 00",
	})
	if err != nil {
		panic(err)
	}
	defer yubikey.Close()

	version, err := yubikey.Version()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Application version %s found.\n", version)
}
```

Running on Windows
==================
1. Download `yubico-piv-tool-1.7.0-win64.zip` from the official site
2. Create directory win in the root of the project
3. Copy `lib` and `include` directories from the downloaded archive to the `win` directory
4. Copy all DLLs  from the `bin` directory in the archive to the root of your project
5. Copy `libwinpthread-1.dll` from `C:\TDM-GCC-64\bin` to the root of your project

Related work
============

Eric Chiang has published [piv-go](https://github.com/ericchiang/piv-go),
a go implementation of the yubikey piv bindings.


LICENSE
=======

```
Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2017

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
