package bytearray

import (
	"encoding/asn1"
)

func DERDecode(bytes []byte) ([]asn1.RawValue, error) {
	rawData := asn1.RawValue{}
	if _, err := asn1.Unmarshal(bytes, &rawData); err != nil {
		return nil, err
	}
	return Decode(rawData.Bytes)

}

func Encode(values []asn1.RawValue) ([]byte, error) {
	ret := []byte{}
	for _, value := range values {
		bytes, err := asn1.Marshal(value)
		if err != nil {
			return nil, err
		}
		ret = append(ret, bytes...)
	}
	return ret, nil
}

func Decode(bytes []byte) ([]asn1.RawValue, error) {
	ret := []asn1.RawValue{}
	for {
		rawData := asn1.RawValue{}
		rest, err := asn1.Unmarshal(bytes, &rawData)
		if err != nil {
			return nil, err
		}
		ret = append(ret, rawData)
		if len(rest) == 0 {
			break
		}
		bytes = rest
	}
	return ret, nil
}
