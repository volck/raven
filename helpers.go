package main

import "encoding/base64"

func isBase64(s string) bool {
		_, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return false
		}
		return true
	}