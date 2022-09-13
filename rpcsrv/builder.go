package rpcsrv

import (
	"bytes"

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

	// Optional id of the document
	ID string

	// Optional qr code with the id of the document, should be set if id is set
	IDQRCode []byte

	// FileName of the original document
	FileName string
}

// BuilderRegisterResp used to retrieve data from Builder.Register
type BuilderRegisterResp struct {
	// Error is not "" if any error occurred during the operation
	Error string

	// ID of the new builder slot
	ID string
}

// Register new builder slot and retrieve it's id
func (t *Builder) Register(args *BuilderRegisterArgs, resp *BuilderRegisterResp) error {
	be := builderEntry{
		di: ddc.DocumentInfo{
			Title:       args.Title,
			Description: args.Description,
			ID:          args.ID,
			IDQRCode:    args.IDQRCode,
			Signatures:  []ddc.SignatureInfo{},
		},

		embeddedFileName: args.FileName,
	}

	resp.ID = newStoreEntry(&be, nil)

	return nil
}

// BuilderAppendDocumentPartArgs used to pass data to Builder.AppendDocumentPart
type BuilderAppendDocumentPartArgs struct {
	// ID of the builder slot to use
	ID string

	// Part of the original document
	Bytes []byte
}

// BuilderAppendDocumentPartResp used to retrieve data from Builder.AppendDocumentPart
type BuilderAppendDocumentPartResp struct {
	// Error is not "" if any error occurred during the operation
	Error string
}

// AppendDocumentPart to the specified builder slot
func (t *Builder) AppendDocumentPart(args *BuilderAppendDocumentPartArgs, resp *BuilderAppendDocumentPartResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.be == nil {
		resp.Error = "unknown id"
		return nil
	}

	_, err = e.be.embeddedFileBuffer.Write(args.Bytes)
	if err != nil {
		resp.Error = err.Error()
		return nil
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

// BuilderAppendSignatureResp used to retrieve data from Builder.AppendSignature
type BuilderAppendSignatureResp struct {
	// Error is not "" if any error occurred during the operation
	Error string
}

// AppendSignature to the specified builder slot
func (t *Builder) AppendSignature(args *BuilderAppendSignatureArgs, resp *BuilderAppendSignatureResp) error {
	err := clamAVScan(args.SignatureInfo.Body)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}

	e, err := getStoreEntry(args.ID)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.be == nil {
		resp.Error = "unknown id"
		return nil
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

	// WithoutDocumentVisualization builds a DDC without document visualization, should be set to `true` for non-PDF documents
	WithoutDocumentVisualization bool

	// WithoutSignaturesVisualization builds a DDC without signatures visualization
	WithoutSignaturesVisualization bool
}

// BuilderBuildResp used to retrieve data from Builder.Build
type BuilderBuildResp struct {
	// Error is not "" if any error occurred during the operation
	Error string
}

// Build DDC in the specified slot, should be called once after all data've been passed
// to the slot via calls to AppendDocumentPart and AppendSignature
func (t *Builder) Build(args *BuilderBuildArgs, resp *BuilderBuildResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	err = clamAVScan(e.be.embeddedFileBuffer.Bytes())
	if err != nil {
		resp.Error = err.Error()
		return nil
	}

	if e.be == nil {
		resp.Error = "unknown id"
		return nil
	}

	ddcBuilder, err := ddc.NewBuilder(&e.be.di)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}

	if args.WithoutDocumentVisualization {
		err = ddcBuilder.EmbedDoc(bytes.NewReader(e.be.embeddedFileBuffer.Bytes()), e.be.embeddedFileName)
	} else {
		err = ddcBuilder.EmbedPDF(bytes.NewReader(e.be.embeddedFileBuffer.Bytes()), e.be.embeddedFileName)
	}
	if err != nil {
		resp.Error = err.Error()
		return nil
	}

	err = ddcBuilder.Build(!args.WithoutDocumentVisualization, !args.WithoutSignaturesVisualization, args.CreationDate, args.BuilderName, args.HowToVerify, &e.be.ddcFileBuffer)
	if err != nil {
		resp.Error = err.Error()
		return nil
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
	// Error is not "" if any error occurred during the operation
	Error string

	// Part of DDC not larger than MaxPartSize
	Part []byte

	// IsFinal signals that there are no more parts to return
	IsFinal bool
}

// GetDDCPart retrieves parts of the DDC in the specified slot successively, should be called after Build
func (t *Builder) GetDDCPart(args *BuilderGetDDCPartArgs, resp *BuilderGetDDCPartResp) error {
	e, err := getStoreEntry(args.ID)
	if err != nil {
		resp.Error = err.Error()
		return nil
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.be == nil {
		resp.Error = "unknown id"
		return nil
	}

	resp.Part = e.be.ddcFileBuffer.Next(args.MaxPartSize)
	if e.be.ddcFileBuffer.Len() == 0 {
		resp.IsFinal = true
	}

	return nil
}

// BuilderDropArgs used to pass data to Builder.Drop
type BuilderDropArgs struct {
	// ID of the builder slot to use
	ID string
}

// BuilderDropResp used to retrieve data from Builder.Drop
type BuilderDropResp struct {
	// Error is not "" if any error occurred during the operation
	Error string
}

// Drop DDC in the specified slot
func (t *Builder) Drop(args *BuilderDropArgs, resp *BuilderDropResp) error {
	deleteStoreEntry(args.ID)
	return nil
}
