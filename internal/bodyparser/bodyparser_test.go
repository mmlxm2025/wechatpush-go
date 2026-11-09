package bodyparser

import (
	"bytes"
	"net/http"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestBodyParserUTF8AndGBK(t *testing.T) {
	jsonUTF8 := `{"message":"测试中文通知","msg_type":"text"}`
	gbkBytes, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(jsonUTF8))
	if err != nil {
		t.Fatalf("encode GB18030 failed: %v", err)
	}
	if IsValidUTF8(gbkBytes) {
		t.Fatal("expected GBK bytes not to be valid UTF-8")
	}

	out, transcoded := TranscodeGB18030BodyIfNeeded(gbkBytes)
	if !transcoded || string(out) != jsonUTF8 {
		t.Fatalf("expected transcoded UTF-8 %q, got transcoded=%v %q", jsonUTF8, transcoded, string(out))
	}

	req, _ := http.NewRequest("POST", "/api/notify/abc", bytes.NewReader(gbkBytes))
	req.Header.Set("Content-Type", "application/json")
	parsed, err := ReadAndParseJSON(req, DefaultJSONBodyLimit)
	if err != nil {
		t.Fatalf("ReadAndParseJSON failed: %v", err)
	}
	if !parsed.Transcoded || !bytes.Equal(parsed.RawBody, gbkBytes) {
		t.Fatal("expected RawBody preserved as original GBK bytes and Transcoded=true")
	}
	if parsed.Data["message"] != "测试中文通知" {
		t.Fatalf("unexpected message: %v", parsed.Data["message"])
	}
}
