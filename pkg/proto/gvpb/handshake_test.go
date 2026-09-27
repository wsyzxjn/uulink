package gvpb

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The original captured profile is a regression fixture, never a runtime template.
func TestConnectOptionsMatchesCompatibleCapture(t *testing.T) {
	const capture = "080110ffffffffffffffffff011a190802100620012a0608802810c01632003801408087a70e583c220c0878100218801e20f0102801220c0878100218801e20f0102803220c0878100118801e20f0102801220c0878100118801e20f0102803320808802810c01618783a0608802810c01640044a103030303030303030303030303030303050015a10080610021801200230023802400248016206342e33382e30"
	want, err := hex.DecodeString(capture)
	if err != nil {
		t.Fatal(err)
	}
	got := ConnectOptions("0000000000000000", "4.38.0", nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("compatibility profile changed:\ngot  %x\nwant %x", got, want)
	}
}
