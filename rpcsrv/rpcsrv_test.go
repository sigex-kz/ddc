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
	docChunkSize     = 1 * 1024 * 1024
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
		ID:          di.ID,
		IDQRCode:    di.IDQRCode,
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
		ID: brResp.ID,
	}
	badpResp := BuilderAppendDocumentPartResp{}

	for n := 0; ; n++ {
		if n*docChunkSize > len(embeddedPdfBytes) {
			break
		}

		if (n+1)*docChunkSize > len(embeddedPdfBytes) {
			badpArgs.Bytes = embeddedPdfBytes[n*docChunkSize:]
		} else {
			badpArgs.Bytes = embeddedPdfBytes[n*docChunkSize : (n+1)*docChunkSize]
		}

		err = client.Call("Builder.AppendDocumentPart", &badpArgs, &badpResp)
		if err != nil {
			t.Fatal(err)
		}
		if badpResp.Error != "" {
			t.Fatal(badpResp.Error)
		}
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
		MaxPartSize: docChunkSize,
	}
	bgddcpResp := BuilderGetDDCPartResp{}

	ddcPDFBuffer := bytes.Buffer{}

	isFinal := false
	for !isFinal {
		err = client.Call("Builder.GetDDCPart", &bgddcpArgs, &bgddcpResp)
		if err != nil {
			t.Fatal(err)
		}
		if bgddcpResp.Error != "" {
			t.Fatal(bgddcpResp.Error)
		}

		ddcPDFBuffer.Write(bgddcpResp.Part)
		isFinal = bgddcpResp.IsFinal
	}

	// Drop builder

	bdArgs := BuilderDropArgs{
		ID: brResp.ID,
	}
	bdResp := BuilderDropResp{}

	err = client.Call("Builder.Drop", &bdArgs, &bdResp)
	if err != nil {
		t.Fatal(err)
	}
	if bdResp.Error != "" {
		t.Fatal(bdResp.Error)
	}

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
		ID: erResp.ID,
	}
	eaddcpResp := ExtractorAppendDDCPartResp{}

	ddcPDFBytes := ddcPDFBuffer.Bytes()
	for n := 0; ; n++ {
		if n*chunkSize > len(ddcPDFBytes) {
			break
		}

		if (n+1)*chunkSize > len(ddcPDFBytes) {
			eaddcpArgs.Part = ddcPDFBytes[n*chunkSize:]
		} else {
			eaddcpArgs.Part = ddcPDFBytes[n*chunkSize : (n+1)*chunkSize]
		}

		err = client.Call("Extractor.AppendDDCPart", &eaddcpArgs, &eaddcpResp)
		if err != nil {
			t.Fatal(err)
		}
		if eaddcpResp.Error != "" {
			t.Fatal(eaddcpResp.Error)
		}
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
		MaxPartSize: docChunkSize,
	}
	egdpResp := ExtractorGetDocumentPartResp{}

	embeddedPDFBuffer := bytes.Buffer{}

	isFinal = false
	for !isFinal {
		err = client.Call("Extractor.GetDocumentPart", &egdpArgs, &egdpResp)
		if err != nil {
			t.Fatal(err)
		}
		if egdpResp.Error != "" {
			t.Fatal(egdpResp.Error)
		}

		embeddedPDFBuffer.Write(egdpResp.Part)
		isFinal = egdpResp.IsFinal
	}

	if !bytes.Equal(embeddedPdfBytes, embeddedPDFBuffer.Bytes()) {
		t.Fatalf("extracted embedded file (size %v) differs from the original (size %v)", len(embeddedPdfBytes), embeddedPDFBuffer.Len())
	}

	// Rewind and retrieve embedded PDF again

	egdpArgs.Rewind = true
	embeddedPDFBuffer = bytes.Buffer{}

	isFinal = false
	for !isFinal {
		err = client.Call("Extractor.GetDocumentPart", &egdpArgs, &egdpResp)
		if err != nil {
			t.Fatal(err)
		}
		if egdpResp.Error != "" {
			t.Fatal(egdpResp.Error)
		}

		embeddedPDFBuffer.Write(egdpResp.Part)
		isFinal = egdpResp.IsFinal
		egdpArgs.Rewind = false
	}

	if !bytes.Equal(embeddedPdfBytes, embeddedPDFBuffer.Bytes()) {
		t.Fatalf("extracted embedded file (size %v) differs from the original (size %v)", len(embeddedPdfBytes), len(embeddedPDFBuffer.Bytes()))
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

	// Drop extractor

	edArgs := ExtractorDropArgs{
		ID: erResp.ID,
	}
	edResp := ExtractorDropResp{}

	err = client.Call("Extractor.Drop", &edArgs, &edResp)
	if err != nil {
		t.Fatal(err)
	}
	if edResp.Error != "" {
		t.Fatal(edResp.Error)
	}
}

func TestWithoutDocumentVisualization(t *testing.T) {

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

	embeddedDocBytes, err := os.ReadFile("../tests-data/embed.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Register builder id

	brArgs := BuilderRegisterArgs{
		Title:       di.Title,
		Description: di.Description,
		ID:          di.ID,
		IDQRCode:    di.IDQRCode,
		FileName:    "embed.txt",
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

	// Send Doc to embed

	badpArgs := BuilderAppendDocumentPartArgs{
		ID: brResp.ID,
	}
	badpResp := BuilderAppendDocumentPartResp{}

	for n := 0; ; n++ {
		if n*docChunkSize > len(embeddedDocBytes) {
			break
		}

		if (n+1)*docChunkSize > len(embeddedDocBytes) {
			badpArgs.Bytes = embeddedDocBytes[n*docChunkSize:]
		} else {
			badpArgs.Bytes = embeddedDocBytes[n*docChunkSize : (n+1)*docChunkSize]
		}

		err = client.Call("Builder.AppendDocumentPart", &badpArgs, &badpResp)
		if err != nil {
			t.Fatal(err)
		}
		if badpResp.Error != "" {
			t.Fatal(badpResp.Error)
		}
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
		ID:                           brResp.ID,
		CreationDate:                 "2021.01.31 13:45:00 UTC+6",
		BuilderName:                  "RPC builder",
		HowToVerify:                  "Somehow",
		WithoutDocumentVisualization: true,
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
		MaxPartSize: docChunkSize,
	}
	bgddcpResp := BuilderGetDDCPartResp{}

	ddcPDFBuffer := bytes.Buffer{}

	isFinal := false
	for !isFinal {
		err = client.Call("Builder.GetDDCPart", &bgddcpArgs, &bgddcpResp)
		if err != nil {
			panic(err)
		}
		if bgddcpResp.Error != "" {
			panic(bgddcpResp.Error)
		}

		ddcPDFBuffer.Write(bgddcpResp.Part)
		isFinal = bgddcpResp.IsFinal
	}

	// Drop builder

	bdArgs := BuilderDropArgs{
		ID: brResp.ID,
	}
	bdResp := BuilderDropResp{}

	err = client.Call("Builder.Drop", &bdArgs, &bdResp)
	if err != nil {
		t.Fatal(err)
	}
	if bdResp.Error != "" {
		t.Fatal(bdResp.Error)
	}

	// Save DDC as file

	err = os.WriteFile("../tests-output/rpcsrv-no-doc-vis.pdf", ddcPDFBuffer.Bytes(), 0o600)
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
		ID: erResp.ID,
	}
	eaddcpResp := ExtractorAppendDDCPartResp{}

	ddcPDFBytes := ddcPDFBuffer.Bytes()
	for n := 0; ; n++ {
		if n*chunkSize > len(ddcPDFBytes) {
			break
		}

		if (n+1)*chunkSize > len(ddcPDFBytes) {
			eaddcpArgs.Part = ddcPDFBytes[n*chunkSize:]
		} else {
			eaddcpArgs.Part = ddcPDFBytes[n*chunkSize : (n+1)*chunkSize]
		}

		err = client.Call("Extractor.AppendDDCPart", &eaddcpArgs, &eaddcpResp)
		if err != nil {
			t.Fatal(err)
		}
		if eaddcpResp.Error != "" {
			t.Fatal(eaddcpResp.Error)
		}
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

	if epResp.DocumentFileName != "embed.txt" {
		t.Fatalf("bad file name '%v', expected '%v'", epResp.DocumentFileName, "embed.txt")
	}

	// Retrieve embedded PDF

	egdpArgs := ExtractorGetDocumentPartArgs{
		ID:          erResp.ID,
		MaxPartSize: docChunkSize,
	}
	egdpResp := ExtractorGetDocumentPartResp{}

	embeddedPDFBuffer := bytes.Buffer{}

	isFinal = false
	for !isFinal {
		err = client.Call("Extractor.GetDocumentPart", &egdpArgs, &egdpResp)
		if err != nil {
			t.Fatal(err)
		}
		if egdpResp.Error != "" {
			t.Fatal(egdpResp.Error)
		}

		embeddedPDFBuffer.Write(egdpResp.Part)
		isFinal = egdpResp.IsFinal
	}

	if !bytes.Equal(embeddedDocBytes, embeddedPDFBuffer.Bytes()) {
		t.Fatalf("extracted embedded file (size %v) differs from the original (size %v)", len(embeddedDocBytes), len(embeddedPDFBuffer.Bytes()))
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

	// Drop extractor

	edArgs := ExtractorDropArgs{
		ID: erResp.ID,
	}
	edResp := ExtractorDropResp{}

	err = client.Call("Extractor.Drop", &edArgs, &edResp)
	if err != nil {
		t.Fatal(err)
	}
	if edResp.Error != "" {
		t.Fatal(edResp.Error)
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

		// Drop builder

		bdArgs := BuilderDropArgs{
			ID: brResp.ID,
		}
		bdResp := BuilderDropResp{}

		err = client.Call("Builder.Drop", &bdArgs, &bdResp)
		if err != nil {
			t.Fatal(err)
		}
		if bdResp.Error != "" {
			t.Fatal(bdResp.Error)
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

		// Drop builder

		bdArgs := BuilderDropArgs{
			ID: brResp.ID,
		}
		bdResp := BuilderDropResp{}

		err = client.Call("Builder.Drop", &bdArgs, &bdResp)
		if err != nil {
			t.Fatal(err)
		}
		if bdResp.Error != "" {
			t.Fatal(bdResp.Error)
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

		// Drop extractor

		edArgs := ExtractorDropArgs{
			ID: erResp.ID,
		}
		edResp := ExtractorDropResp{}

		err = client.Call("Extractor.Drop", &edArgs, &edResp)
		if err != nil {
			t.Fatal(err)
		}
		if edResp.Error != "" {
			t.Fatal(edResp.Error)
		}
	})
}

func TestKK(t *testing.T) {

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
		ID:          di.ID,
		IDQRCode:    di.IDQRCode,
		FileName:    "embed.pdf",
		Language:    "kk",
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
		ID: brResp.ID,
	}
	badpResp := BuilderAppendDocumentPartResp{}

	for n := 0; ; n++ {
		if n*docChunkSize > len(embeddedPdfBytes) {
			break
		}

		if (n+1)*docChunkSize > len(embeddedPdfBytes) {
			badpArgs.Bytes = embeddedPdfBytes[n*docChunkSize:]
		} else {
			badpArgs.Bytes = embeddedPdfBytes[n*docChunkSize : (n+1)*docChunkSize]
		}

		err = client.Call("Builder.AppendDocumentPart", &badpArgs, &badpResp)
		if err != nil {
			panic(err)
		}
		if badpResp.Error != "" {
			panic(badpResp.Error)
		}
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
		MaxPartSize: docChunkSize,
	}
	bgddcpResp := BuilderGetDDCPartResp{}

	ddcPDFBuffer := bytes.Buffer{}

	isFinal := false
	for !isFinal {
		err = client.Call("Builder.GetDDCPart", &bgddcpArgs, &bgddcpResp)
		if err != nil {
			panic(err)
		}
		if bgddcpResp.Error != "" {
			panic(bgddcpResp.Error)
		}

		ddcPDFBuffer.Write(bgddcpResp.Part)
		isFinal = bgddcpResp.IsFinal
	}

	// Drop builder

	bdArgs := BuilderDropArgs{
		ID: brResp.ID,
	}
	bdResp := BuilderDropResp{}

	err = client.Call("Builder.Drop", &bdArgs, &bdResp)
	if err != nil {
		t.Fatal(err)
	}
	if bdResp.Error != "" {
		t.Fatal(bdResp.Error)
	}

	// Save DDC as file

	err = os.WriteFile("../tests-output/rpcsrv-kk.pdf", ddcPDFBuffer.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkBuild(b *testing.B) {

	// Configure ClamAV

	ClamAVConfigure("unix", "/var/run/clamav/clamd.ctl")

	// Start server

	errChan := make(chan error)
	go func(errChan chan error) {
		<-errChan
	}(errChan)

	err := Start(network, address, errChan)
	if err != nil {
		b.Fatal(err)
	}

	defer func() {
		stopErr := Stop()
		if stopErr != nil {
			b.Fatal(stopErr)
		}

		time.Sleep(100 * time.Millisecond)
	}()

	client, err := jsonrpc.Dial(network, address)
	if err != nil {
		b.Fatal(err)
	}

	// Load test data

	jsonBytes, err := os.ReadFile("../tests-data/fullfeatured-di.json")
	if err != nil {
		b.Fatal(err)
	}

	di := ddc.DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		b.Fatal(err)
	}

	embeddedPdfBytes, err := os.ReadFile("../tests-data/embed.pdf")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Register builder id

		brArgs := BuilderRegisterArgs{
			Title:       di.Title,
			Description: di.Description,
			ID:          di.ID,
			IDQRCode:    di.IDQRCode,
			FileName:    "embed.pdf",
		}
		brResp := BuilderRegisterResp{}

		err = client.Call("Builder.Register", &brArgs, &brResp)
		if err != nil {
			b.Fatal(err)
		}
		if brResp.Error != "" {
			b.Fatal(brResp.Error)
		}

		// Send PDF to embed

		badpArgs := BuilderAppendDocumentPartArgs{
			ID: brResp.ID,
		}
		badpResp := BuilderAppendDocumentPartResp{}

		for n := 0; ; n++ {
			if n*chunkSize > len(embeddedPdfBytes) {
				break
			}

			if (n+1)*chunkSize > len(embeddedPdfBytes) {
				badpArgs.Bytes = embeddedPdfBytes[n*chunkSize:]
			} else {
				badpArgs.Bytes = embeddedPdfBytes[n*chunkSize : (n+1)*chunkSize]
			}

			err = client.Call("Builder.AppendDocumentPart", &badpArgs, &badpResp)
			if err != nil {
				panic(err)
			}
			if badpResp.Error != "" {
				panic(badpResp.Error)
			}
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
				b.Fatal(err)
			}
			if basResp.Error != "" {
				b.Fatal(basResp.Error)
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
			b.Fatal(err)
		}
		if bbResp.Error != "" {
			b.Fatal(bbResp.Error)
		}

		// Retrieve

		bgddcpArgs := BuilderGetDDCPartArgs{
			ID:          brResp.ID,
			MaxPartSize: chunkSize,
		}
		bgddcpResp := BuilderGetDDCPartResp{}

		ddcPDFBuffer := bytes.Buffer{}

		isFinal := false
		for !isFinal {
			err = client.Call("Builder.GetDDCPart", &bgddcpArgs, &bgddcpResp)
			if err != nil {
				panic(err)
			}
			if bgddcpResp.Error != "" {
				panic(bgddcpResp.Error)
			}

			ddcPDFBuffer.Write(bgddcpResp.Part)
			isFinal = bgddcpResp.IsFinal
		}

		// Drop builder

		bdArgs := BuilderDropArgs{
			ID: brResp.ID,
		}
		bdResp := BuilderDropResp{}

		err = client.Call("Builder.Drop", &bdArgs, &bdResp)
		if err != nil {
			b.Fatal(err)
		}
		if bdResp.Error != "" {
			b.Fatal(bdResp.Error)
		}
	}
}

func BenchmarkParse(b *testing.B) {

	// Configure ClamAV

	ClamAVConfigure("unix", "/var/run/clamav/clamd.ctl")

	// Start server

	errChan := make(chan error)
	go func(errChan chan error) {
		<-errChan
	}(errChan)

	err := Start(network, address, errChan)
	if err != nil {
		b.Fatal(err)
	}

	defer func() {
		stopErr := Stop()
		if stopErr != nil {
			b.Fatal(stopErr)
		}

		time.Sleep(100 * time.Millisecond)
	}()

	client, err := jsonrpc.Dial(network, address)
	if err != nil {
		b.Fatal(err)
	}

	// Load test data

	jsonBytes, err := os.ReadFile("../tests-data/fullfeatured-di.json")
	if err != nil {
		b.Fatal(err)
	}

	di := ddc.DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		b.Fatal(err)
	}

	embeddedPdfBytes, err := os.ReadFile("../tests-data/embed.pdf")
	if err != nil {
		b.Fatal(err)
	}

	// Register builder id

	brArgs := BuilderRegisterArgs{
		Title:       di.Title,
		Description: di.Description,
		ID:          di.ID,
		IDQRCode:    di.IDQRCode,
		FileName:    "embed.pdf",
	}
	brResp := BuilderRegisterResp{}

	err = client.Call("Builder.Register", &brArgs, &brResp)
	if err != nil {
		b.Fatal(err)
	}
	if brResp.Error != "" {
		b.Fatal(brResp.Error)
	}

	if brResp.ID == "" {
		b.Fatal("received bad id")
	}

	// Send PDF to embed

	badpArgs := BuilderAppendDocumentPartArgs{
		ID: brResp.ID,
	}
	badpResp := BuilderAppendDocumentPartResp{}

	for n := 0; ; n++ {
		if n*chunkSize > len(embeddedPdfBytes) {
			break
		}

		if (n+1)*chunkSize > len(embeddedPdfBytes) {
			badpArgs.Bytes = embeddedPdfBytes[n*chunkSize:]
		} else {
			badpArgs.Bytes = embeddedPdfBytes[n*chunkSize : (n+1)*chunkSize]
		}

		err = client.Call("Builder.AppendDocumentPart", &badpArgs, &badpResp)
		if err != nil {
			panic(err)
		}
		if badpResp.Error != "" {
			panic(badpResp.Error)
		}
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
			b.Fatal(err)
		}
		if basResp.Error != "" {
			b.Fatal(basResp.Error)
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
		b.Fatal(err)
	}
	if bbResp.Error != "" {
		b.Fatal(bbResp.Error)
	}

	// Retrieve

	bgddcpArgs := BuilderGetDDCPartArgs{
		ID:          brResp.ID,
		MaxPartSize: chunkSize,
	}
	bgddcpResp := BuilderGetDDCPartResp{}

	ddcPDFBuffer := bytes.Buffer{}

	isFinal := false
	for !isFinal {
		err = client.Call("Builder.GetDDCPart", &bgddcpArgs, &bgddcpResp)
		if err != nil {
			panic(err)
		}
		if bgddcpResp.Error != "" {
			panic(bgddcpResp.Error)
		}

		ddcPDFBuffer.Write(bgddcpResp.Part)
		isFinal = bgddcpResp.IsFinal
	}

	// Drop builder

	bdArgs := BuilderDropArgs{
		ID: brResp.ID,
	}
	bdResp := BuilderDropResp{}

	err = client.Call("Builder.Drop", &bdArgs, &bdResp)
	if err != nil {
		b.Fatal(err)
	}
	if bdResp.Error != "" {
		b.Fatal(bdResp.Error)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Register extractor id

		erArgs := ExtractorRegisterArgs{}
		erResp := ExtractorRegisterResp{}

		err = client.Call("Extractor.Register", &erArgs, &erResp)
		if err != nil {
			b.Fatal(err)
		}
		if erResp.Error != "" {
			b.Fatal(erResp.Error)
		}

		// Send DDC to extractor

		eaddcpArgs := ExtractorAppendDDCPartArgs{
			ID: erResp.ID,
		}
		eaddcpResp := ExtractorAppendDDCPartResp{}

		ddcPDFBytes := ddcPDFBuffer.Bytes()
		for n := 0; ; n++ {
			if n*chunkSize > len(ddcPDFBytes) {
				break
			}

			if (n+1)*chunkSize > len(ddcPDFBytes) {
				eaddcpArgs.Part = ddcPDFBytes[n*chunkSize:]
			} else {
				eaddcpArgs.Part = ddcPDFBytes[n*chunkSize : (n+1)*chunkSize]
			}

			err = client.Call("Extractor.AppendDDCPart", &eaddcpArgs, &eaddcpResp)
			if err != nil {
				b.Fatal(err)
			}
			if eaddcpResp.Error != "" {
				b.Fatal(eaddcpResp.Error)
			}
		}

		// Parse

		epArgs := ExtractorParseArgs{
			ID: erResp.ID,
		}
		epResp := ExtractorParseResp{}

		err = client.Call("Extractor.Parse", &epArgs, &epResp)
		if err != nil {
			b.Fatal(err)
		}
		if epResp.Error != "" {
			b.Fatal(epResp.Error)
		}

		// Retrieve embedded PDF

		egdpArgs := ExtractorGetDocumentPartArgs{
			ID:          erResp.ID,
			MaxPartSize: docChunkSize,
		}
		egdpResp := ExtractorGetDocumentPartResp{}

		embeddedPDFBuffer := bytes.Buffer{}

		isFinal = false
		for !isFinal {
			err = client.Call("Extractor.GetDocumentPart", &egdpArgs, &egdpResp)
			if err != nil {
				b.Fatal(err)
			}
			if egdpResp.Error != "" {
				b.Fatal(egdpResp.Error)
			}

			embeddedPDFBuffer.Write(egdpResp.Part)
			isFinal = egdpResp.IsFinal
		}

		// Retrieve signatures

		for range di.Signatures {
			egsArgs := ExtractorGetSignatureArgs{
				ID: erResp.ID,
			}
			egsResp := ExtractorGetSignatureResp{}

			err = client.Call("Extractor.GetSignature", &egsArgs, &egsResp)
			if err != nil {
				b.Fatal(err)
			}
			if egsResp.Error != "" {
				b.Fatal(egsResp.Error)
			}
		}

		// Drop extractor

		edArgs := ExtractorDropArgs{
			ID: erResp.ID,
		}
		edResp := ExtractorDropResp{}

		err = client.Call("Extractor.Drop", &edArgs, &edResp)
		if err != nil {
			b.Fatal(err)
		}
		if edResp.Error != "" {
			b.Fatal(edResp.Error)
		}

	}
}
