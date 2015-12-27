package parser

import (
	"fmt"
)

var TLSHeaderLengh = 5

/* This function is basically all most folks want to invoke out of this
 * jumble of bits. This will take an incoming TLS Client Hello (including
 * all the fuzzy bits at the beginning of it - fresh out of the socket) and
 * go ahead and give us the SNI Name they want. */
func GetHostname(data []byte) ([]byte, error) {
	extensions, err := GetExtensionBlock(data)
	if err != nil {
		return []byte{}, err
	}
	sn, err := GetSNBlock(extensions)
	if err != nil {
		return []byte{}, err
	}
	sni, err := GetSNIBlock(sn)
	if err != nil {
		return []byte{}, err
	}
	return sni, nil
}

/* Given a Server Name TLS Extension block, parse out and return the SNI
 * (Server Name Indication) payload */
func GetSNIBlock(data []byte) ([]byte, error) {
	index := 0

	for {
		if index >= len(data) {
			break
		}
		length := int((data[index] << 8) + data[index+1])
		endIndex := index + 2 + length
		if data[index+2] == 0x00 { /* SNI */
			sni := data[index+3:]
			sniLength := int((sni[0] << 8) + sni[1])
			return sni[2 : sniLength+2], nil
		}
		index = endIndex
	}
	return []byte{}, fmt.Errorf(
		"Finished parsing the SN block without finding an SNI",
	)
}

/* Given an TLS Extensions data block, go ahead and find the SN block */
func GetSNBlock(data []byte) ([]byte, error) {
	index := 0

	if len(data) < 2 {
		return []byte{}, fmt.Errorf("Not enough bytes to be a SN block")
	}

	extensionLength := int((data[index] << 8) + data[index+1])
	data = data[2:extensionLength]

	for {
		if index >= len(data) {
			break
		}
		length := int((data[index+2] << 8) + data[index+3])
		endIndex := index + 4 + length
		if data[index] == 0x00 && data[index+1] == 0x00 {
			return data[index+4 : endIndex], nil
		}

		index = endIndex
	}

	return []byte{}, fmt.Errorf(
		"Finished parsing the Extension block without finding an SN block",
	)
}

/* Given a raw TLS Client Hello, go ahead and find all the Extensions */
func GetExtensionBlock(data []byte) ([]byte, error) {
	/*   data[0]           - content type
	 *   data[1], data[2]  - major/minor version
	 *   data[3], data[4]  - total length
	 *   data[...38+5]     - start of SessionID (length bit)
	 *   data[38+5]        - length of SessionID
	 */
	var index = TLSHeaderLengh + 38

	if len(data) <= index+1 {
		return []byte{}, fmt.Errorf("Not enough bits to be a Client Hello")
	}

	/* Index is at SessionID Length bit */
	if newIndex := index + 1 + int(data[index]); (newIndex + 2) < len(data) {
		index = newIndex
	} else {
		return []byte{}, fmt.Errorf("Not enough bytes for the SessionID")
	}

	/* Index is at Cipher List Length bits */
	if newIndex := (index + 2 + int((data[index]<<8)+data[index+1])); (newIndex + 1) < len(data) {
		index = newIndex
	} else {
		return []byte{}, fmt.Errorf("Not enough bytes for the Cipher List")
	}

	/* Index is now at the compression length bit */
	if newIndex := index + 1 + int(data[index]); newIndex < len(data) {
		index = newIndex
	} else {
		return []byte{}, fmt.Errorf("Not enough bytes for the compression length")
	}

	/* Now we're at the Extension start */
	if len(data[index:]) == 0 {
		return nil, fmt.Errorf("No extensions")
	}
	return data[index:], nil
}
