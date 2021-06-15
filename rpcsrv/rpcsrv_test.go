package rpcsrv

import (
	"bytes"
	"encoding/json"
	"net/rpc/jsonrpc"
	"os"
	"testing"
	"time"

	"github.com/sigex-kz/ddc"
)

const (
	network = "tcp"
	address = "127.0.0.1:1234"
)

func TestPingPong(t *testing.T) {

	// Start server

	errChan := make(chan error)
	go func(errChan chan error) {
		srvErr := <-errChan
		t.Log(srvErr)
	}(errChan)

	err := Start(network, address, errChan)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		stopErr := Stop()
		if stopErr != nil {
			t.Fatal(stopErr)
		}

		time.Sleep(100 * time.Millisecond)
	}()

	client, err := jsonrpc.Dial(network, address)
	if err != nil {
		t.Fatal(err)
	}

	// Load test data

	jsonBytes, err := os.ReadFile("../tests-data/fullfeatured-di.json")
	if err != nil {
		t.Fatal(err)
	}

	di := ddc.DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		t.Fatal(err)
	}

	embeddedPdfBytes, err := os.ReadFile("../tests-data/embed.pdf")
	if err != nil {
		t.Fatal(err)
	}

	// Register builder id

	brArgs := BuilderRegisterArgs{
		Title:       di.Title,
		Description: di.Description,
		FileName:    "embed.pdf",
	}

	id := ""
	err = client.Call("Builder.Register", &brArgs, &id)
	if err != nil {
		t.Fatal(err)
	}

	if id == "" {
		t.Fatal("received bad id")
	}

	// Send PDF to embed

	badpArgs := BuilderAppendDocumentPartArgs{
		ID:    id,
		Bytes: embeddedPdfBytes[:len(embeddedPdfBytes)/2],
	}

	notUsed := 0
	err = client.Call("Builder.AppendDocumentPart", &badpArgs, &notUsed)
	if err != nil {
		t.Fatal(err)
	}

	badpArgs.Bytes = embeddedPdfBytes[len(embeddedPdfBytes)/2:]

	err = client.Call("Builder.AppendDocumentPart", &badpArgs, &notUsed)
	if err != nil {
		t.Fatal(err)
	}

	// Send signatures

	for _, s := range di.Signatures {
		basArgs := BuilderAppendSignatureArgs{
			ID:            id,
			SignatureInfo: s,
		}

		err = client.Call("Builder.AppendSignature", &basArgs, &notUsed)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Build

	bbArgs := BuilderBuildArgs{
		ID:           id,
		CreationDate: "2021.01.31 13:45:00 UTC+6",
		BuilderName:  "RPC builder",
		HowToVerify:  "Somehow",
	}

	err = client.Call("Builder.Build", &bbArgs, &notUsed)
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve

	bgddcpArgs := BuilderGetDDCPartArgs{
		ID:          id,
		MaxPartSize: 10,
	}
	bgddcpResp := BuilderGetDDCPartResp{}

	err = client.Call("Builder.GetDDCPart", &bgddcpArgs, &bgddcpResp)
	if err != nil {
		t.Fatal(err)
	}

	if bgddcpResp.IsFinal {
		t.Fatal("should not be final")
	}

	ddcPDFBuffer := bytes.Buffer{}
	ddcPDFBuffer.Write(bgddcpResp.Part)

	bgddcpArgs.MaxPartSize = 100 * 1024 * 1024
	bgddcpResp = BuilderGetDDCPartResp{}

	err = client.Call("Builder.GetDDCPart", &bgddcpArgs, &bgddcpResp)
	if err != nil {
		t.Fatal(err)
	}

	if !bgddcpResp.IsFinal {
		t.Fatal("should be final")
	}

	ddcPDFBuffer.Write(bgddcpResp.Part)

	// Save DDC as file

	err = os.WriteFile("../tests-output/rpcsrv-fullfeatured.pdf", ddcPDFBuffer.Bytes(), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Register extractor id

	erArgs := ExtractorRegisterArgs{}

	id = ""
	err = client.Call("Extractor.Register", &erArgs, &id)
	if err != nil {
		t.Fatal(err)
	}

	if id == "" {
		t.Fatal("received bad id")
	}

	// Send DDC to extractor

	eaddcpArgs := ExtractorAppendDDCPartArgs{
		ID:   id,
		Part: ddcPDFBuffer.Next(10),
	}

	err = client.Call("Extractor.AppendDDCPart", &eaddcpArgs, &notUsed)
	if err != nil {
		t.Fatal(err)
	}

	eaddcpArgs.Part = ddcPDFBuffer.Next(ddcPDFBuffer.Len())

	err = client.Call("Extractor.AppendDDCPart", &eaddcpArgs, &notUsed)
	if err != nil {
		t.Fatal(err)
	}

	// Parse

	epArgs := ExtractorParseArgs{
		ID: id,
	}

	docFileName := ""
	err = client.Call("Extractor.Parse", &epArgs, &docFileName)
	if err != nil {
		t.Fatal(err)
	}

	if docFileName != "embed.pdf" {
		t.Fatalf("bad file name '%v', expected '%v'", docFileName, "embed.pdf")
	}

	// Retrieve embedded PDF

	egdpArgs := ExtractorGetDocumentPartArgs{
		ID:          id,
		MaxPartSize: 10,
	}

	egdpResp := ExtractorGetDocumentPartResp{}

	err = client.Call("Extractor.GetDocumentPart", &egdpArgs, &egdpResp)
	if err != nil {
		t.Fatal(err)
	}

	if egdpResp.IsFinal {
		t.Fatal("should not be final")
	}

	embeddedPDFBuffer := bytes.Buffer{}
	embeddedPDFBuffer.Write(egdpResp.Part)

	egdpArgs.MaxPartSize = 100 * 1024 * 1024
	err = client.Call("Extractor.GetDocumentPart", &egdpArgs, &egdpResp)
	if err != nil {
		t.Fatal(err)
	}

	if !egdpResp.IsFinal {
		t.Fatal("should be final")
	}

	embeddedPDFBuffer.Write(egdpResp.Part)

	if !bytes.Equal(embeddedPdfBytes, embeddedPDFBuffer.Bytes()) {
		t.Fatalf("extracted embedded file (size %v) differs from the original (size %v)", len(embeddedPdfBytes), embeddedPDFBuffer.Len())
	}

	// Rewind and retrieve embedded PDF again

	egdpArgs.Rewind = true
	egdpArgs.MaxPartSize = 100 * 1024 * 1024

	err = client.Call("Extractor.GetDocumentPart", &egdpArgs, &egdpResp)
	if err != nil {
		t.Fatal(err)
	}

	if !egdpResp.IsFinal {
		t.Fatal("should be final")
	}

	if !bytes.Equal(embeddedPdfBytes, egdpResp.Part) {
		t.Fatalf("extracted embedded file (size %v) differs from the original (size %v)", len(embeddedPdfBytes), len(egdpResp.Part))
	}

	// Retrieve signatures

	for i, s := range di.Signatures {
		egsArgs := ExtractorGetSignatureArgs{
			ID: id,
		}

		egsResp := ExtractorGetSignatureResp{}

		err = client.Call("Extractor.GetSignature", &egsArgs, &egsResp)
		if err != nil {
			t.Fatal(err)
		}

		if (i+1 != len(di.Signatures)) && egsResp.IsFinal {
			t.Fatal("should not be final")
		}

		if (i+1 == len(di.Signatures)) && !egsResp.IsFinal {
			t.Fatal("should be final")
		}

		if !bytes.Equal(s.Body, egsResp.Signature.Bytes) {
			t.Fatalf("extracted signature (size %v) differs from the original (size %v)", len(egsResp.Signature.Bytes), len(s.Body))
		}
	}
}
