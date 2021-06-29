package rpcsrv

import (
	"bytes"
	"errors"

	"github.com/sigex-kz/ddc"
)

// Extractor can be exported via net/rpc and used to extract embedded files from DDC
type Extractor int

// ExtractorRegisterArgs used to pass data to Extractor.Register
type ExtractorRegisterArgs struct {
}

// Register new extraactor slot and retrieve it's id
func (t *Extractor) Register(args *ExtractorRegisterArgs, id *string) error {
	ee := extractorEntry{}

	*id = newStoreEntry(nil, &ee)

	return nil
}

// ExtractorAppendDDCPartArgs used to pass data to Extractor.AppendDDCPart
type ExtractorAppendDDCPartArgs struct {
	// ID of the extractor slot to use
	ID string

	// Part of the DDC
	Part []byte
}

// AppendDDCPart to the specified extractor slot
func (t *Extractor) AppendDDCPart(args *ExtractorAppendDDCPartArgs, notUsed *int) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		return err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.ee == nil {
		return errors.New("unknown id")
	}

	e.ee.ddcFileBuffer.Write(args.Part)

	return nil
}

// ExtractorParseArgs used to pass data to Extractor.Parse
type ExtractorParseArgs struct {
	// ID of the extractor slot to use
	ID string
}

// Parse DDC in the specified slot, should be called after all parts of DDC've been
// transmitted via AppendDDCPart
func (t *Extractor) Parse(args *ExtractorParseArgs, documentFileName *string) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		return err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	err = clamAVScan(e.ee.ddcFileBuffer.Bytes())
	if err != nil {
		return err
	}

	if e.ee == nil {
		return errors.New("unknown id")
	}

	documentOriginal, signatures, err := ddc.ExtractAttachments(bytes.NewReader(e.ee.ddcFileBuffer.Bytes()))
	if err != nil {
		return err
	}

	err = clamAVScan(documentOriginal.Bytes)
	if err != nil {
		return err
	}

	for _, s := range signatures {
		err = clamAVScan(s.Bytes)
		if err != nil {
			return err
		}
	}

	e.ee.documentOriginal = documentOriginal
	e.ee.signatures = signatures

	*documentFileName = documentOriginal.Name

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
	// Part of the original document not larger than MaxPartSize
	Part []byte

	// IsFinal signals that there are no more parts to return
	IsFinal bool
}

// GetDocumentPart retrieves parts of the original document in the specified slot successively, should be called after Parse
func (t *Extractor) GetDocumentPart(args *ExtractorGetDocumentPartArgs, resp *ExtractorGetDocumentPartResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		return err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.ee == nil {
		return errors.New("unknown id")
	}

	if e.ee.documentOriginal == nil {
		return errors.New("DDC not parsed")
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
	// Signature bytes and file name
	Signature ddc.AttachedFile

	// IsFinal signals that there are no more signatures to return
	IsFinal bool
}

// GetSignature retrieves signatures that've benn embedded into DDC successively, should be called after Parse
func (t *Extractor) GetSignature(args *ExtractorGetSignatureArgs, resp *ExtractorGetSignatureResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		return err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.ee == nil {
		return errors.New("unknown id")
	}

	if e.ee.signatures == nil {
		return errors.New("DDC not parsed")
	}

	resp.Signature = e.ee.signatures[0]

	e.ee.signatures = e.ee.signatures[1:]

	if len(e.ee.signatures) == 0 {
		resp.IsFinal = true
	}

	return nil
}

// ExtractorDropArgs used to pass data to Extractor.GetDDCPart
type ExtractorDropArgs struct {
	// ID of the extractor slot to use
	ID string
}

// Drop DDC in the specified slot
func (t *Extractor) Drop(args *ExtractorDropArgs, notUsed *int) error {
	deleteStoreEntry(args.ID)
	return nil
}
