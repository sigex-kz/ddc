package rpcsrv

import (
	"bytes"
	"errors"

	"github.com/sigex-kz/ddc"
)

// Builder can be exported via net/rpc and used to build DDC
type Builder int

// BuilderRegisterArgs used to pass data to Builder.Register
type BuilderRegisterArgs struct {
	// Title of the document
	Title string

	// Description of the document
	Description string

	// FileName of the original document
	FileName string
}

// Register new builder slot and retrieve it's id
func (t *Builder) Register(args *BuilderRegisterArgs, id *string) error {
	be := builderEntry{
		di: ddc.DocumentInfo{
			Title:       args.Title,
			Description: args.Description,
			Signatures:  []ddc.SignatureInfo{},
		},

		embeddedFileName: args.FileName,
	}

	*id = newStoreEntry(&be, nil)

	return nil
}

// BuilderAppendDocumentPartArgs used to pass data to Builder.AppendDocumentPart
type BuilderAppendDocumentPartArgs struct {
	// ID of the builder slot to use
	ID string

	// Part of the original document
	Bytes []byte
}

// AppendDocumentPart to the specified builder slot
func (t *Builder) AppendDocumentPart(args *BuilderAppendDocumentPartArgs, notUsed *int) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		return err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.be == nil {
		return errors.New("unknown id")
	}

	_, err = e.be.embeddedFileBuffer.Write(args.Bytes)
	if err != nil {
		return err
	}

	return nil
}

// BuilderAppendSignatureArgs used to pass data to Builder.AppendSignature
type BuilderAppendSignatureArgs struct {
	// ID of the builder slot to use
	ID string

	// SignatureInfo describes the signature
	SignatureInfo ddc.SignatureInfo
}

// AppendSignature to the specified builder slot
func (t *Builder) AppendSignature(args *BuilderAppendSignatureArgs, notUsed *int) error {
	err := clamAVScan(args.SignatureInfo.Body)
	if err != nil {
		return err
	}

	e, err := getStoreEntry(args.ID)
	if err != nil {
		return err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.be == nil {
		return errors.New("unknown id")
	}

	e.be.di.Signatures = append(e.be.di.Signatures, args.SignatureInfo)

	return nil
}

// BuilderBuildArgs used to pass data to Builder.Build
type BuilderBuildArgs struct {
	// ID of the builder slot to use
	ID string

	// CreationDate should be current date and time in format "2021.01.31 13:45:00 UTC+6"
	// converted to time zone of Nur-Sultan.
	CreationDate string

	// BuilderName would be embedded into DDC visualization
	BuilderName string

	// HowToVerify should provide instructions to verify DDC
	HowToVerify string
}

// Build DDC in the specified slot, should be called once after all data've been passed
// to the slot via calls to AppendDocumentPart and AppendSignature
func (t *Builder) Build(args *BuilderBuildArgs, notUsed *int) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		return err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	err = clamAVScan(e.be.embeddedFileBuffer.Bytes())
	if err != nil {
		return err
	}

	if e.be == nil {
		return errors.New("unknown id")
	}

	ddcBuilder, err := ddc.NewBuilder(e.be.di)
	if err != nil {
		return err
	}

	err = ddcBuilder.EmbedPDF(bytes.NewReader(e.be.embeddedFileBuffer.Bytes()), e.be.embeddedFileName)
	if err != nil {
		return err
	}

	err = ddcBuilder.Build(true, true, args.CreationDate, args.BuilderName, args.HowToVerify, &e.be.ddcFileBuffer)
	if err != nil {
		return err
	}

	return nil
}

// BuilderGetDDCPartArgs used to pass data to Builder.GetDDCPart
type BuilderGetDDCPartArgs struct {
	// ID of the builder slot to use
	ID string

	// MaxPartSize should be used to limit the size of the part
	MaxPartSize int
}

// BuilderGetDDCPartResp used to retrieve data from Builder.GetDDCPart
type BuilderGetDDCPartResp struct {
	// Part of DDC not larger than MaxPartSize
	Part []byte

	// IsFinal signals that there are no more parts to return
	IsFinal bool
}

// GetDDCPart retrieves parts of the DDC in the specified slot successively, should be called after Build
func (t *Builder) GetDDCPart(args *BuilderGetDDCPartArgs, resp *BuilderGetDDCPartResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		return err
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.be == nil {
		return errors.New("unknown id")
	}

	resp.Part = e.be.ddcFileBuffer.Next(args.MaxPartSize)
	if e.be.ddcFileBuffer.Len() == 0 {
		resp.IsFinal = true
	}

	return nil
}

// BuilderDropArgs used to pass data to Builder.GetDDCPart
type BuilderDropArgs struct {
	// ID of the builder slot to use
	ID string
}

// Drop DDC in the specified slot
func (t *Builder) Drop(args *BuilderDropArgs, notUsed *int) error {
	deleteStoreEntry(args.ID)
	return nil
}
