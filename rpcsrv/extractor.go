package rpcsrv

import (
	"bytes"
	"log"

	"github.com/sigex-kz/ddc"
)

// Extractor can be exported via net/rpc and used to extract embedded files from DDC
type Extractor int

// ExtractorRegisterArgs used to pass data to Extractor.Register
type ExtractorRegisterArgs struct {
}

// ExtractorRegisterResp used to retrieve data from Extractor.Register
type ExtractorRegisterResp struct {
	// Error is not "" if any error occurred during the operation
	Error string

	// ID of the new extractor slot
	ID string
}

// Register new extractor slot and retrieve it's id
func (t *Extractor) Register(_ *ExtractorRegisterArgs, resp *ExtractorRegisterResp) error {
	ee := extractorEntry{}

	resp.ID = newStoreEntry(nil, &ee)

	return nil
}

// ExtractorAppendDDCPartArgs used to pass data to Extractor.AppendDDCPart
type ExtractorAppendDDCPartArgs struct {
	// ID of the extractor slot to use
	ID string

	// Part of the DDC
	Part []byte
}

// ExtractorAppendDDCPartResp used to retrieve data from Extractor.AppendDDCPart
type ExtractorAppendDDCPartResp struct {
	// Error is not "" if any error occurred during the operation
	Error string
}

// AppendDDCPart to the specified extractor slot
func (t *Extractor) AppendDDCPart(args *ExtractorAppendDDCPartArgs, resp *ExtractorAppendDDCPartResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Extractor.AppendDDCPart: %s", resp.Error)
		return nil
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.ee == nil {
		resp.Error = "unknown id"
		log.Printf("Extractor.AppendDDCPart: %s", resp.Error)
		return nil
	}

	_, err = e.ee.ddcFileBuffer.Write(args.Part)
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Extractor.AppendDDCPart: %s", resp.Error)
		return nil
	}

	return nil
}

// ExtractorParseArgs used to pass data to Extractor.Parse
type ExtractorParseArgs struct {
	// ID of the extractor slot to use
	ID string
}

// ExtractorParseResp used to retrieve data from Extractor.Parse
type ExtractorParseResp struct {
	// Error is not "" if any error occurred during the operation
	Error string

	// DocumentFileName extracted from DDC
	DocumentFileName string
}

// Parse DDC in the specified slot, should be called after all parts of DDC've been
// transmitted via AppendDDCPart
func (t *Extractor) Parse(args *ExtractorParseArgs, resp *ExtractorParseResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Extractor.Parse: %s", resp.Error)
		return nil
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	err = clamAVScan(e.ee.ddcFileBuffer.Bytes())
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Extractor.Parse: %s", resp.Error)
		return nil
	}

	if e.ee == nil {
		resp.Error = "unknown id"
		log.Printf("Extractor.Parse: %s", resp.Error)
		return nil
	}

	documentOriginal, signatures, err := ddc.ExtractAttachments(bytes.NewReader(e.ee.ddcFileBuffer.Bytes()))
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Extractor.Parse: %s", resp.Error)
		return nil
	}

	err = clamAVScan(documentOriginal.Bytes)
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Extractor.Parse: %s", resp.Error)
		return nil
	}

	for _, s := range signatures {
		err = clamAVScan(s.Bytes)
		if err != nil {
			resp.Error = err.Error()
			log.Printf("Extractor.Parse: %s", resp.Error)
			return nil
		}
	}

	e.ee.documentOriginal = documentOriginal
	e.ee.signatures = signatures

	resp.DocumentFileName = documentOriginal.Name

	return nil
}

// ExtractorGetDocumentPartArgs used to pass data to Extractor.GetDocumentPart
type ExtractorGetDocumentPartArgs struct {
	// ID of the extractor slot to use
	ID string

	// MaxPartSize should be used to limit the size of the part
	MaxPartSize int

	// Rewind to the beginning of the document
	Rewind bool
}

// ExtractorGetDocumentPartResp used to retrieve data from Extractor.GetDocumentPart
type ExtractorGetDocumentPartResp struct {
	// Error is not "" if any error occurred during the operation
	Error string

	// Part of the original document not larger than MaxPartSize
	Part []byte

	// IsFinal signals that there are no more parts to return
	IsFinal bool
}

// GetDocumentPart retrieves parts of the original document in the specified slot successively, should be called after Parse
func (t *Extractor) GetDocumentPart(args *ExtractorGetDocumentPartArgs, resp *ExtractorGetDocumentPartResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Extractor.GetDocumentPart: %s", resp.Error)
		return nil
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.ee == nil {
		resp.Error = "unknown id"
		log.Printf("Extractor.GetDocumentPart: %s", resp.Error)
		return nil
	}

	if e.ee.documentOriginal == nil {
		resp.Error = "DDC not parsed"
		log.Printf("Extractor.GetDocumentPart: %s", resp.Error)
		return nil
	}

	if args.Rewind {
		e.ee.documentOriginalBytesRead = 0
	}

	bytesRemain := len(e.ee.documentOriginal.Bytes) - e.ee.documentOriginalBytesRead
	partSize := args.MaxPartSize
	if partSize >= bytesRemain {
		partSize = bytesRemain
		resp.IsFinal = true
	}

	resp.Part = e.ee.documentOriginal.Bytes[e.ee.documentOriginalBytesRead : e.ee.documentOriginalBytesRead+partSize]
	e.ee.documentOriginalBytesRead += partSize

	return nil
}

// ExtractorGetSignatureArgs used to pass data to Extractor.GetSignature
type ExtractorGetSignatureArgs struct {
	// ID of the extractor slot to use
	ID string
}

// ExtractorGetSignatureResp used to retrieve data from Extractor.GetSignature
type ExtractorGetSignatureResp struct {
	// Error is not "" if any error occurred during the operation
	Error string

	// Signature bytes and file name
	Signature ddc.AttachedFile

	// IsFinal signals that there are no more signatures to return
	IsFinal bool
}

// GetSignature retrieves signatures that've benn embedded into DDC successively, should be called after Parse
func (t *Extractor) GetSignature(args *ExtractorGetSignatureArgs, resp *ExtractorGetSignatureResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Extractor.GetSignature: %s", resp.Error)
		return nil
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.ee == nil {
		resp.Error = "unknown id"
		log.Printf("Extractor.GetSignature: %s", resp.Error)
		return nil
	}

	if e.ee.signatures == nil {
		resp.Error = "DDC not parsed"
		log.Printf("Extractor.GetSignature: %s", resp.Error)
		return nil
	}

	resp.Signature = e.ee.signatures[0]

	e.ee.signatures = e.ee.signatures[1:]

	if len(e.ee.signatures) == 0 {
		resp.IsFinal = true
	}

	return nil
}

// ExtractorDropArgs used to pass data to Extractor.Drop
type ExtractorDropArgs struct {
	// ID of the extractor slot to use
	ID string
}

// ExtractorDropResp used to retrieve data from Extractor.Drop
type ExtractorDropResp struct {
	// Error is not "" if any error occurred during the operation
	Error string
}

// Drop DDC in the specified slot
func (t *Extractor) Drop(args *ExtractorDropArgs, _ *ExtractorDropResp) error {
	deleteStoreEntry(args.ID)
	return nil
}
