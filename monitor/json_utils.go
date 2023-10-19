package monitor

import (
	"bytes"
	"github.com/PlatONnetwork/PlatON-Go/common/json"
	"github.com/PlatONnetwork/PlatON-Go/log"
)

func ToJson(obj interface{}) []byte {
	if obj == nil {
		return []byte{}
	}
	bs, err := json.Marshal(obj)
	if err != nil {
		log.Error("cannot marshal object", "err", err)
		return []byte{}
	} else {
		return bs
	}

}

func ToJsonString(obj interface{}) string {
	if obj == nil {
		return string([]byte{})
	}
	bs, err := json.Marshal(obj)
	if err != nil {
		log.Error("cannot marshal object", "err", err)
		return string([]byte{})
	} else {
		return string(bs)
	}
}

func PrettyJsonString(jsonBytes []byte) string {
	var out bytes.Buffer
	err := json.Indent(&out, jsonBytes, "", "\t")
	if err != nil {
		return string(jsonBytes)
	}
	return out.String()
}

func ParseJson(bs []byte, objRefer interface{}) {
	if len(bs) == 0 {
		return
	}
	err := json.Unmarshal(bs, objRefer)
	if err != nil {
		log.Error("cannot unmarshal to object", "err", err)
	}
}

func ParseJsonString(js string, objRefer interface{}) {
	if len(js) == 0 {
		return
	}
	err := json.Unmarshal([]byte(js), objRefer)
	if err != nil {
		log.Error("cannot unmarshal to object", "err", err)
	}
}
