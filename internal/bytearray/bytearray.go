package bytearray

import (
	"encoding/asn1"
)

func Decode(bytes []byte) ([]asn1.RawValue, error) {
	ret := []asn1.RawValue{}

	rawData := asn1.RawValue{}
	if _, err := asn1.Unmarshal(bytes, &rawData); err != nil {
		return nil, err
	}

	bytes = rawData.Bytes
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
