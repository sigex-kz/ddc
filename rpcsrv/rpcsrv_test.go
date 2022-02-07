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
	network          = "tcp"
	address          = "127.0.0.1:1234"
	eicar            = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	clamAVEicarFound = "unexpected response from clamd 'stream: Win.Test.EICAR_HDB-1 FOUND\n'"
)

func TestPingPong(t *testing.T) {

	// Configure ClamAV

	ClamAVConfigure("unix", "/var/run/clamav/clamd.ctl")

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
	brResp := BuilderRegisterResp{}

	err = client.Call("Builder.Register", &brArgs, &brResp)
	if err != nil {
		t.Fatal(err)
	}
	if brResp.Error != "" {
		t.Fatal(brResp.Error)
	}

	if brResp.ID == "" {
		t.Fatal("received bad id")
	}

	// Send PDF to embed

	badpArgs := BuilderAppendDocumentPartArgs{
		ID:    brResp.ID,
		Bytes: embeddedPdfBytes[:len(embeddedPdfBytes)/2],
	}
	badpResp := BuilderAppendDocumentPartResp{}

	err = client.Call("Builder.AppendDocumentPart", &badpArgs, &badpResp)
	if err != nil {
		t.Fatal(err)
	}
	if badpResp.Error != "" {
		t.Fatal(badpResp.Error)
	}

	badpArgs.Bytes = embeddedPdfBytes[len(embeddedPdfBytes)/2:]

	err = client.Call("Builder.AppendDocumentPart", &badpArgs, &badpResp)
	if err != nil {
		t.Fatal(err)
	}
	if badpResp.Error != "" {
		t.Fatal(badpResp.Error)
	}

	// Send signatures

	for _, s := range di.Signatures {
		basArgs := BuilderAppendSignatureArgs{
			ID:            brResp.ID,
			SignatureInfo: s,
		}
		basResp := BuilderAppendSignatureResp{}

		err = client.Call("Builder.AppendSignature", &basArgs, &basResp)
		if err != nil {
			t.Fatal(err)
		}
		if basResp.Error != "" {
			t.Fatal(basResp.Error)
		}
	}

	// Build

	bbArgs := BuilderBuildArgs{
		ID:           brResp.ID,
		CreationDate: "2021.01.31 13:45:00 UTC+6",
		BuilderName:  "RPC builder",
		HowToVerify:  "Somehow",
	}
	bbResp := BuilderBuildResp{}

	err = client.Call("Builder.Build", &bbArgs, &bbResp)
	if err != nil {
		t.Fatal(err)
	}
	if bbResp.Error != "" {
		t.Fatal(bbResp.Error)
	}

	// Retrieve

	bgddcpArgs := BuilderGetDDCPartArgs{
		ID:          brResp.ID,
		MaxPartSize: 10,
	}
	bgddcpResp := BuilderGetDDCPartResp{}

	err = client.Call("Builder.GetDDCPart", &bgddcpArgs, &bgddcpResp)
	if err != nil {
		t.Fatal(err)
	}
	if bgddcpResp.Error != "" {
		t.Fatal(bgddcpResp.Error)
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
	if bgddcpResp.Error != "" {
		t.Fatal(bgddcpResp.Error)
	}

	if !bgddcpResp.IsFinal {
		t.Fatal("should be final")
	}

	ddcPDFBuffer.Write(bgddcpResp.Part)

	// Save DDC as file

	err = os.WriteFile("../tests-output/rpcsrv-fullfeatured.pdf", ddcPDFBuffer.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// Register extractor id

	erArgs := ExtractorRegisterArgs{}
	erResp := ExtractorRegisterResp{}

	err = client.Call("Extractor.Register", &erArgs, &erResp)
	if err != nil {
		t.Fatal(err)
	}
	if erResp.Error != "" {
		t.Fatal(erResp.Error)
	}

	if erResp.ID == "" {
		t.Fatal("received bad id")
	}

	// Send DDC to extractor

	eaddcpArgs := ExtractorAppendDDCPartArgs{
		ID:   erResp.ID,
		Part: ddcPDFBuffer.Next(10),
	}
	eaddcpResp := ExtractorAppendDDCPartResp{}

	err = client.Call("Extractor.AppendDDCPart", &eaddcpArgs, &eaddcpResp)
	if err != nil {
		t.Fatal(err)
	}
	if eaddcpResp.Error != "" {
		t.Fatal(eaddcpResp.Error)
	}

	eaddcpArgs.Part = ddcPDFBuffer.Next(ddcPDFBuffer.Len())

	err = client.Call("Extractor.AppendDDCPart", &eaddcpArgs, &eaddcpResp)
	if err != nil {
		t.Fatal(err)
	}
	if eaddcpResp.Error != "" {
		t.Fatal(eaddcpResp.Error)
	}

	// Parse

	epArgs := ExtractorParseArgs{
		ID: erResp.ID,
	}
	epResp := ExtractorParseResp{}

	err = client.Call("Extractor.Parse", &epArgs, &epResp)
	if err != nil {
		t.Fatal(err)
	}
	if epResp.Error != "" {
		t.Fatal(epResp.Error)
	}

	if epResp.DocumentFileName != "embed.pdf" {
		t.Fatalf("bad file name '%v', expected '%v'", epResp.DocumentFileName, "embed.pdf")
	}

	// Retrieve embedded PDF

	egdpArgs := ExtractorGetDocumentPartArgs{
		ID:          erResp.ID,
		MaxPartSize: 10,
	}
	egdpResp := ExtractorGetDocumentPartResp{}

	err = client.Call("Extractor.GetDocumentPart", &egdpArgs, &egdpResp)
	if err != nil {
		t.Fatal(err)
	}
	if egdpResp.Error != "" {
		t.Fatal(egdpResp.Error)
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
	if egdpResp.Error != "" {
		t.Fatal(egdpResp.Error)
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
	if egdpResp.Error != "" {
		t.Fatal(egdpResp.Error)
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
			ID: erResp.ID,
		}
		egsResp := ExtractorGetSignatureResp{}

		err = client.Call("Extractor.GetSignature", &egsArgs, &egsResp)
		if err != nil {
			t.Fatal(err)
		}
		if egsResp.Error != "" {
			t.Fatal(egsResp.Error)
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

func TestClamAV(t *testing.T) {

	// Configure ClamAV

	ClamAVConfigure("unix", "/var/run/clamav/clamd.ctl")

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

	t.Run("bad signature", func(t *testing.T) {

		// Register builder id

		brArgs := BuilderRegisterArgs{
			Title:       di.Title,
			Description: di.Description,
			FileName:    "embed.pdf",
		}
		brResp := BuilderRegisterResp{}

		err = client.Call("Builder.Register", &brArgs, &brResp)
		if err != nil {
			t.Fatal(err)
		}
		if brResp.Error != "" {
			t.Fatal(brResp.Error)
		}

		if brResp.ID == "" {
			t.Fatal("received bad id")
		}

		// Send signature

		s := di.Signatures[0]
		s.Body = []byte(eicar)
		basArgs := BuilderAppendSignatureArgs{
			ID:            brResp.ID,
			SignatureInfo: s,
		}
		basResp := BuilderAppendSignatureResp{}

		err = client.Call("Builder.AppendSignature", &basArgs, &basResp)
		if err != nil {
			t.Fatal(err)
		}
		if basResp.Error != clamAVEicarFound {
			t.Fatal("should fail because of the antivirus test")
		}
	})

	t.Run("bad document", func(t *testing.T) {

		// Register builder id

		brArgs := BuilderRegisterArgs{
			Title:       di.Title,
			Description: di.Description,
			FileName:    "embed.pdf",
		}
		brResp := BuilderRegisterResp{}

		err = client.Call("Builder.Register", &brArgs, &brResp)
		if err != nil {
			t.Fatal(err)
		}
		if brResp.Error != "" {
			t.Fatal(brResp.Error)
		}

		if brResp.ID == "" {
			t.Fatal("received bad id")
		}

		// Send PDF to embed

		badpArgs := BuilderAppendDocumentPartArgs{
			ID:    brResp.ID,
			Bytes: []byte(eicar),
		}
		badpResp := BuilderAppendDocumentPartResp{}

		err = client.Call("Builder.AppendDocumentPart", &badpArgs, &badpResp)
		if err != nil {
			t.Fatal(err)
		}
		if badpResp.Error != "" {
			t.Fatal(badpResp.Error)
		}

		// Send signatures

		for _, s := range di.Signatures {
			basArgs := BuilderAppendSignatureArgs{
				ID:            brResp.ID,
				SignatureInfo: s,
			}
			basResp := BuilderAppendSignatureResp{}

			err = client.Call("Builder.AppendSignature", &basArgs, &basResp)
			if err != nil {
				t.Fatal(err)
			}
			if basResp.Error != "" {
				t.Fatal(basResp.Error)
			}
		}

		// Build

		bbArgs := BuilderBuildArgs{
			ID:           brResp.ID,
			CreationDate: "2021.01.31 13:45:00 UTC+6",
			BuilderName:  "RPC builder",
			HowToVerify:  "Somehow",
		}
		bbResp := BuilderBuildResp{}

		err = client.Call("Builder.Build", &bbArgs, &bbResp)
		if err != nil {
			t.Fatal(err)
		}
		if bbResp.Error != clamAVEicarFound {
			t.Fatal("should fail because of the antivirus test")
		}
	})

	t.Run("bad ddc", func(t *testing.T) {

		// Register extractor id

		erArgs := ExtractorRegisterArgs{}
		erResp := ExtractorRegisterResp{}

		err = client.Call("Extractor.Register", &erArgs, &erResp)
		if err != nil {
			t.Fatal(err)
		}
		if erResp.Error != "" {
			t.Fatal(erResp.Error)
		}

		if erResp.ID == "" {
			t.Fatal("received bad id")
		}

		// Send DDC to extractor

		eaddcpArgs := ExtractorAppendDDCPartArgs{
			ID:   erResp.ID,
			Part: []byte(eicar),
		}
		eaddcpResp := ExtractorAppendDDCPartResp{}

		err = client.Call("Extractor.AppendDDCPart", &eaddcpArgs, &eaddcpResp)
		if err != nil {
			t.Fatal(err)
		}
		if eaddcpResp.Error != "" {
			t.Fatal(eaddcpResp.Error)
		}

		// Parse

		epArgs := ExtractorParseArgs{
			ID: erResp.ID,
		}
		epResp := ExtractorParseResp{}

		err = client.Call("Extractor.Parse", &epArgs, &epResp)
		if err != nil {
			t.Fatal(err)
		}
		if epResp.Error != clamAVEicarFound {
			t.Fatal("should fail because of the antivirus test")
		}
	})
}
