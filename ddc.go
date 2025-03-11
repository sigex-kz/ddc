// Package ddc implements Digital document card specification (https://github.com/kaarkz/ddcard)
package ddc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vsenko/gofpdf"
	pdfcpuapi "github.com/vsenko/pdfcpu/pkg/api"
	"github.com/vsenko/pdfcpu/pkg/pdfcpu"
	pdfcpumodel "github.com/vsenko/pdfcpu/pkg/pdfcpu/model"
	pdfcputypes "github.com/vsenko/pdfcpu/pkg/pdfcpu/types"
)

const (
	constPageType                   = "A4"
	constPageOrientation            = "P"
	constPageUnits                  = "mm"
	constPageWidth                  = 210
	constPageHeight                 = 297
	constPageTopMargin              = 10
	constPageBottomMargin           = 10
	constPageLeftMargin             = 30
	constPageRightMargin            = 10
	constContentMaxWidth            = constPageWidth - constPageLeftMargin - constPageRightMargin
	constContentMaxHeight           = constPageHeight - constPageTopMargin - constPageBottomMargin
	constHeaderHeight               = 10
	constIDQRSize                   = constHeaderHeight + 2
	constLinkQRSize                 = 17
	constLinkQRTextMargin           = 4.5
	constBuilderLogoHeight          = 13
	constBuilderLogoWidth           = 26
	constFooterHeight               = 10
	constFooterDescriptionMaxLength = 90
	constEmbeddedPageMaxWidth       = constContentMaxWidth
	constEmbeddedPageMaxHeight      = constContentMaxHeight - constHeaderHeight - constFooterHeight
	constContentTop                 = constPageTopMargin + constHeaderHeight + 5
	constContentLeftColumnWidth     = constContentMaxWidth / 3 * 2
	constContentRightColumnWidth    = constContentMaxWidth / 3
	constContentRightColumnX        = constPageLeftMargin + constContentLeftColumnWidth

	constSignatureQRCodeImageSize = 42
	constSignatureQRCodesInARow   = 4
	constSignatureQRCodeMargin    = (constContentMaxWidth - constSignatureQRCodeImageSize*constSignatureQRCodesInARow) / (constSignatureQRCodesInARow + 2)
	constSignatureQRCodeTopMargin = 5

	constInfoBlockContentsPageNumColWidth        = 10
	constInfoBlockAttachmentsIndexNumColWidth    = 11
	constInfoBlockAttachmentsDescriptionColWidth = 75
	constInfoBlockAttachmentsFileNameColWidth    = constContentMaxWidth - constInfoBlockAttachmentsIndexNumColWidth - constInfoBlockAttachmentsDescriptionColWidth

	constFontRegular     = "LiberationSans-Regular"
	constFontBold        = "LiberationSans-Bold"
	constFontItalic      = "LiberationSans-Italic"
	constFontBoldItalic  = "LiberationSans-BoldItalic"
	constFontMonoRegular = "LiberationMono-Regular"

	const45ccv = 45
	const90ccv = 90

	constGrayR = 211
	constGrayG = 211
	constGrayB = 211

	constSemiTransparent = 0.5

	constMinimalAttachmentsDuringExport = 2

	constTwo = 2
)

// SignatureVisualization information used to construct signature visualization page
type SignatureVisualization struct {
	// Signers full name
	SubjectName string `json:"subjectName"`

	// Signers identification number such as IIN or passport number
	SubjectID string `json:"subjectID"`

	// In case if the subject signed as an employee, name of the employer
	SubjectOrgName string `json:"subjectOrgName"`

	// In case if the subject signed as an employee, identification number of the employer, such as BIN or tax number
	SubjectOrgID string `json:"subjectOrgID"`

	// Subjects full RDN in RFC 4514 format
	Subject string `json:"subject"`

	// Subjects alternative names from subjectAltName certificate extension
	SubjectAltName string `json:"subjectAltName"`

	// Serial number of the signers certificate
	SerialNumber string `json:"serialNumber"`

	// From value from certificate in format "19.05.2021 04:01:52 UTC+6"
	From string `json:"from"`

	// Until value from certificate in format "19.05.2021 04:01:52 UTC+6"
	Until string `json:"until"`

	// Certificate policies (aka certificate templates) in the following format "Human readable name (OID)"
	Policies []string `json:"policies"`

	// Key usages in the following format "Human readable name (const from https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3)"
	KeyUsage []string `json:"keyUsage"`

	// Extended key usages in the following format "Human readable name (OID)"
	ExtKeyUsage []string `json:"extKeyUsage"`

	// Certificate issuers full RDN in RFC 4514 format
	Issuer string `json:"issuer"`

	// Signature algorithm in the following format "Human readable name (OID)"
	SignatureAlgorithm string `json:"signatureAlgorithm"`

	// Time stamp imformation
	TSP struct {

		// Time stamp from TSP response in format "19.05.2021 04:01:52 UTC+6"
		// converted to time zone of Nur-Sultan
		GeneratedAt string `json:"generatedAt"`

		// Serial number of the TSP signers certificate
		SerialNumber string `json:"serialNumber"`

		// TSP signers certificate subject full RDN in RFC 4514 format
		Subject string `json:"subject"`

		// TSP signers certificate issuer full RDN in RFC 4514 format
		Issuer string `json:"issuer"`
	} `json:"tsp"`

	// OCSP response information
	OCSP struct {

		// ThisUpdate value from OCSP response in format "19.05.2021 04:01:52 UTC+6"
		// converted to time zone of Nur-Sultan
		GeneratedAt string `json:"generatedAt"`

		// CertStatus from OCSP response as a string (one of "good", "revoked", or "unknown")
		CertStatus string `json:"certStatus"`

		// Serial number of the OCSP signers certificate
		SerialNumber string `json:"serialNumber"`

		// OCSP signers certificate subject full RDN in RFC 4514 format
		Subject string `json:"subject"`

		// OCSP signers certificate issuer full RDN in RFC 4514 format
		Issuer string `json:"issuer"`
	} `json:"ocsp"`

	// Signature body encoded as a sey of QR codes and stored as PNG images (optional)
	QRCodes [][]byte `json:"qrCodes"`
}

// SignatureInfo used to embed signature in DDC and optionally to construct visualization
type SignatureInfo struct {
	// Signature body bytes
	Body []byte `json:"body"`

	// File name for attachment
	FileName string `json:"fileName"`

	// Signer name to build attachment description (optional, required if SignatureVisualization is not provided)
	SignerName string `json:"signerName"`

	// Signature visualization information (optional, required for signatures visualization)
	SignatureVisualization *SignatureVisualization `json:"signatureVisualization"`
}

// DocumentInfo contains information about the digital document and signatures
type DocumentInfo struct {
	// Title of the document
	Title string `json:"title"`

	// Optional description of the document
	Description string `json:"description"`

	// Optional id of the document
	ID string `json:"id"`

	// Optional qr code with the id of the document, should be set if id is set
	IDQRCode []byte `json:"idQRCode"`

	// Optional qr code with the link to the document accessible from internet
	LinkQRCode []byte `json:"linkQRCode"`

	// Optional builder logo, printer on the left side of each page
	BuilderLogo []byte `json:"builderLogo"`

	// Optional string printed under the builder logo
	SubBuilderLogoString string `json:"subBuilderLogoString"`

	// Signatures information
	Signatures []SignatureInfo `json:"signatures"`

	// The language to build DDC in ["ru", "kk", "kk/ru"]
	Language string `json:"language"`
}

// Builder builds Digital Document Card
type Builder struct {
	pdf          *gofpdf.Fpdf
	imageOptions gofpdf.ImageOptions
	di           *DocumentInfo

	attachments []gofpdf.Attachment

	infoBlockNumPages int

	// For any embedded document type
	embeddedDoc         io.ReadSeeker
	embeddedDocFileName string

	// For embedded PDFs
	embeddedPDFNumPages   int
	embeddedPDFPagesSizes []pdfcputypes.Dim

	totalPages int
}

// NewBuilder creates a new DDC Builder
func NewBuilder(di *DocumentInfo) (*Builder, error) {
	ddc := Builder{
		imageOptions: gofpdf.ImageOptions{
			ReadDpi:   true,
			ImageType: "png",
		},
		di: di,
	}

	return &ddc, nil
}

// EmbedPDF registers a digital document original in PDF format that should be embedded into DDC
func (ddc *Builder) EmbedPDF(pdf io.ReadSeeker, fileName string) error {
	// Optimize PDF via pdfcpu because gopdfi Importer is fragile, does not return errors and panics
	config := pdfcpumodel.NewDefaultConfiguration()
	config.DecodeAllStreams = true
	config.WriteObjectStream = false
	config.WriteXRefStream = false

	ctx, err := pdfcpuapi.ReadContext(pdf, config)
	if err != nil {
		return err
	}

	err = pdfcpuapi.ValidateContext(ctx)
	if err != nil {
		return err
	}

	numPages := ctx.PageCount
	pagesSizes, err := ctx.PageDims()
	if err != nil {
		return err
	}

	if numPages < 1 {
		return errors.New("document is empty")
	}

	ddc.embedDoc(pdf, numPages, pagesSizes, fileName)

	return nil
}

// EmbedDoc registers a digital document original in any format that should be embedded into DDC
func (ddc *Builder) EmbedDoc(doc io.ReadSeeker, fileName string) error {
	ddc.embedDoc(doc, 0, nil, fileName)
	return nil
}

func (ddc *Builder) embedDoc(doc io.ReadSeeker, numPages int, pagesSizes []pdfcputypes.Dim, fileName string) {
	ddc.embeddedDoc = doc
	ddc.embeddedDocFileName = fileName

	ddc.embeddedPDFNumPages = numPages
	ddc.embeddedPDFPagesSizes = pagesSizes
}

func (ddc *Builder) initPdf() (pdf *gofpdf.Fpdf, err error) {
	pdf = gofpdf.New(constPageOrientation, constPageUnits, constPageType, "")

	// Fpdf by default sets PDF version to "1.3" and not always bumps it when uses newer features.
	// Adding an empty layer bumps the version to "1.5" thus increasing compliance with the standard.
	pdf.AddLayer("Layer1", true)

	pdf.AddUTF8FontFromBytes(constFontRegular, "", embeddedFontRegular)
	pdf.AddUTF8FontFromBytes(constFontBold, "", embeddedFontBold)
	pdf.AddUTF8FontFromBytes(constFontItalic, "", embeddedFontItalic)
	pdf.AddUTF8FontFromBytes(constFontBoldItalic, "", embeddedFontBoldItalic)
	pdf.AddUTF8FontFromBytes(constFontMonoRegular, "", embeddedFontMonoRegular)

	// Fpdf margins are used only on Info Block pages, configure them with header and footer height to utilize auto page break
	pdf.SetMargins(constPageLeftMargin, constContentTop, constPageRightMargin)
	pdf.SetAutoPageBreak(true, constPageBottomMargin+constFooterHeight)

	if err := pdf.Error(); err != nil {
		return nil, err
	}

	return pdf, nil
}

func (ddc *Builder) addHeaderAndFooterToCurrentPage(headerText, footerText string, addPageNumber bool) error {
	if headerText != "" {
		position := "LM"
		if ddc.di.ID != "" && ddc.di.Language == "kk/ru" {
			position = "LT"
		}

		ddc.pdf.SetXY(constPageLeftMargin, constPageTopMargin)
		ddc.pdf.SetFont(constFontRegular, "", 11)
		ddc.pdf.CellFormat(constContentMaxWidth, constHeaderHeight, headerText, "", 1, position, false, 0, "")
	}

	if ddc.di.ID != "" {
		ddc.pdf.SetXY(constPageLeftMargin, constPageTopMargin)
		ddc.pdf.SetFont(constFontRegular, "", 10)
		ddc.pdf.CellFormat(constContentMaxWidth-constIDQRSize, constHeaderHeight-1, ddc.di.ID, "", 1, "RB", false, 0, "")

		imgOptions := gofpdf.ImageOptions{
			ReadDpi:   true,
			ImageType: "png",
		}
		ddc.pdf.RegisterImageOptionsReader("id-qr-code.png", imgOptions, bytes.NewReader(ddc.di.IDQRCode))
		ddc.pdf.ImageOptions("id-qr-code.png", constPageLeftMargin+constContentMaxWidth-constIDQRSize, constPageTopMargin, constIDQRSize, constIDQRSize, false, imgOptions, 0, "")

		ddc.pdf.Line(constPageLeftMargin, constPageTopMargin+constHeaderHeight, constPageLeftMargin+constContentMaxWidth-constIDQRSize, constPageTopMargin+constHeaderHeight)
	} else {
		ddc.pdf.Line(constPageLeftMargin, constPageTopMargin+constHeaderHeight, constPageLeftMargin+constContentMaxWidth, constPageTopMargin+constHeaderHeight)
	}

	ddc.pdf.Line(constPageLeftMargin, constPageHeight-constPageBottomMargin-constFooterHeight, constPageLeftMargin+constContentMaxWidth, constPageHeight-constPageBottomMargin-constFooterHeight)

	if footerText != "" {
		ddc.pdf.SetXY(constPageLeftMargin, constPageHeight-constPageBottomMargin-constFooterHeight)
		ddc.pdf.SetFont(constFontRegular, "", 8)
		ddc.pdf.CellFormat(constContentMaxWidth, constFooterHeight/2, footerText, "", 1, "LB", false, 0, "")

		var descriptionBuilder strings.Builder
		descriptionLength := 0
		for _, runeValue := range ddc.di.Description {
			if descriptionLength == constFooterDescriptionMaxLength-3 {
				if _, err := descriptionBuilder.WriteString("..."); err != nil {
					return err
				}
				break
			}

			if _, err := descriptionBuilder.WriteRune(runeValue); err != nil {
				return err
			}

			descriptionLength++
		}
		ddc.pdf.SetFont(constFontBold, "", 8)
		ddc.pdf.CellFormat(constContentMaxWidth, constFooterHeight/2, descriptionBuilder.String(), "", 1, "LT", false, 0, "")
	}

	if addPageNumber {
		ddc.pdf.SetXY(constPageLeftMargin, constPageHeight-constPageBottomMargin-constFooterHeight)
		ddc.pdf.SetFont(constFontRegular, "", 11)
		pageNumberText := fmt.Sprintf(ddc.t("стр. %v из %v"), ddc.pdf.PageNo(), ddc.totalPages)
		ddc.pdf.CellFormat(constContentMaxWidth, constFooterHeight, pageNumberText, "", 1, "RM", false, 0, "")
	}

	// Left side
	ddc.pdf.TransformBegin()
	ddc.pdf.TransformRotate(const90ccv, 0, constPageHeight)

	if ddc.di.LinkQRCode != nil {
		imgOptions := gofpdf.ImageOptions{
			ReadDpi:   true,
			ImageType: "png",
		}
		ddc.pdf.RegisterImageOptionsReader("link-qr-code.png", imgOptions, bytes.NewReader(ddc.di.LinkQRCode))
		ddc.pdf.ImageOptions("link-qr-code.png", constPageBottomMargin, constPageHeight+constPageTopMargin, constLinkQRSize, constLinkQRSize, false, imgOptions, 0, "")
		ddc.pdf.ImageOptions("link-qr-code.png", constPageHeight-constPageTopMargin-constLinkQRSize, constPageHeight+constPageTopMargin, constLinkQRSize, constLinkQRSize, false, imgOptions, 0, "")

		ddc.pdf.SetFont(constFontMonoRegular, "", 6)
		ddc.pdf.SetXY(constPageBottomMargin+constLinkQRSize, constPageHeight+constPageTopMargin+constLinkQRTextMargin)
		ddc.pdf.CellFormat(constContentMaxWidth, constLinkQRSize, "<-- қол қойылған құжатты тексеріңіз", "", 1, "LT", false, 0, "")
		ddc.pdf.SetXY(constPageBottomMargin+constLinkQRSize, constPageHeight+constPageTopMargin)
		ddc.pdf.CellFormat(constContentMaxWidth, constLinkQRSize-constLinkQRTextMargin, "<-- проверить подписанный документ", "", 1, "LB", false, 0, "")

		ddc.pdf.SetFont(constFontMonoRegular, "", 6)
		ddc.pdf.SetXY(constPageHeight-constPageTopMargin-constLinkQRSize-constContentMaxWidth, constPageHeight+constPageTopMargin+constLinkQRTextMargin)
		ddc.pdf.CellFormat(constContentMaxWidth, constLinkQRSize, "қол қойылған құжатты тексеріңіз -->", "", 1, "RT", false, 0, "")
		ddc.pdf.SetXY(constPageHeight-constPageTopMargin-constLinkQRSize-constContentMaxWidth, constPageHeight+constPageTopMargin)
		ddc.pdf.CellFormat(constContentMaxWidth, constLinkQRSize-constLinkQRTextMargin, "проверить подписанный документ -->", "", 1, "RB", false, 0, "")
	}

	if ddc.di.BuilderLogo != nil {
		imgOptions := gofpdf.ImageOptions{
			ReadDpi:   true,
			ImageType: "png",
		}
		ddc.pdf.RegisterImageOptionsReader("id-qr-code-3.png", imgOptions, bytes.NewReader(ddc.di.BuilderLogo))
		ddc.pdf.ImageOptions("id-qr-code-3.png", (constPageHeight-constBuilderLogoWidth)/2, constPageHeight+constPageTopMargin, constBuilderLogoWidth, constBuilderLogoHeight, false, imgOptions, 0, "")
	}

	if ddc.di.SubBuilderLogoString != "" {
		ddc.pdf.SetFont(constFontMonoRegular, "", 8)
		ddc.pdf.SetXY((constPageHeight-constContentMaxWidth)/2, constPageHeight+constPageTopMargin)
		ddc.pdf.CellFormat(constContentMaxWidth, constLinkQRSize, ddc.di.SubBuilderLogoString, "", 1, "CB", false, 0, "")
	}

	ddc.pdf.TransformEnd()

	if err := ddc.pdf.Error(); err != nil {
		return err
	}

	return nil
}

// Build DDC and write it's bytes to w
func (ddc *Builder) Build(visualizeDocument, visualizeSignatures bool, creationDate, builderName, howToVerify string, w io.Writer) error {
	var err error

	if visualizeDocument && ddc.embeddedPDFNumPages == 0 {
		return errors.New("visualization of non-PDF files is not available")
	}

	// PDF init
	ddc.pdf, err = ddc.initPdf()
	if err != nil {
		return err
	}

	// Attachments
	err = ddc.attachFiles(false)
	if err != nil {
		return err
	}

	// Simulate Info Block to find out how many pages it'll take
	tempDDC, err := NewBuilder(ddc.di)
	if err != nil {
		return err
	}

	tempDDC.embedDoc(ddc.embeddedDoc, ddc.embeddedPDFNumPages, ddc.embeddedPDFPagesSizes, ddc.embeddedDocFileName)

	tempDDC.pdf, err = tempDDC.initPdf()
	if err != nil {
		return err
	}

	err = tempDDC.attachFiles(true)
	if err != nil {
		return err
	}

	err = tempDDC.constructInfoBlock(visualizeDocument, visualizeSignatures, creationDate, builderName, howToVerify)
	if err != nil {
		return err
	}

	ddc.infoBlockNumPages = tempDDC.pdf.PageCount()

	// Visualization
	ddc.totalPages = ddc.infoBlockNumPages
	if visualizeDocument {
		ddc.totalPages += ddc.embeddedPDFNumPages
	}
	if visualizeSignatures {
		ddc.totalPages += len(ddc.di.Signatures)
	}

	err = ddc.constructInfoBlock(visualizeDocument, visualizeSignatures, creationDate, builderName, howToVerify)
	if err != nil {
		return err
	}

	if visualizeDocument {
		err = ddc.constructDocumentVisualization()
		if err != nil {
			return err
		}
	}

	if visualizeSignatures {
		err = ddc.constructSignaturesVisualization()
		if err != nil {
			return err
		}
	}

	// Build output
	var pdfBytes bytes.Buffer
	err = ddc.pdf.Output(&pdfBytes)
	if err != nil {
		return err
	}

	// Just in case
	err = ddc.pdf.Error()
	if err != nil {
		return err
	}

	ctx, err := pdfcpuapi.ReadContext(bytes.NewReader(pdfBytes.Bytes()), pdfcpumodel.NewDefaultConfiguration())
	if err != nil {
		return err
	}

	// Add pages of the embedded PDF
	if visualizeDocument {
		desc := fmt.Sprintf("offset: %v 0 ,rot:0, scale:0.8 rel", constPageLeftMargin)

		var wm *pdfcpumodel.Watermark
		wm, err = pdfcpu.ParsePDFWatermarkDetails(ddc.embeddedDocFileName, desc, false, pdfcputypes.POINTS)
		if err != nil {
			return err
		}

		wm.PDF = ddc.embeddedDoc
		wm.PdfMultiStartPageNrDest = ddc.infoBlockNumPages + 1
		wm.PdfMultiStartPageNrSrc = 1

		err = ctx.EnsurePageCount()
		if err != nil {
			return err
		}

		pageInDDC := fmt.Sprintf("%v-%v", ddc.infoBlockNumPages+1, ddc.infoBlockNumPages+ddc.embeddedPDFNumPages)
		selectedPages := []string{pageInDDC}
		pages, errPages := pdfcpuapi.PagesForPageSelection(ctx.PageCount, selectedPages, true, true)
		if errPages != nil {
			return errPages
		}

		err = pdfcpu.AddWatermarks(ctx, pages, wm)
		if err != nil {
			return err
		}
	}

	err = pdfcpuapi.ValidateContext(ctx)
	if err != nil {
		return err
	}

	err = pdfcpuapi.WriteContext(ctx, w)
	if err != nil {
		return err
	}

	return nil
}

func (ddc *Builder) attachFiles(dryRun bool) error {
	ddc.attachments = make([]gofpdf.Attachment, len(ddc.di.Signatures)+1)

	var pdfBytes []byte
	if !dryRun {
		_, err := ddc.embeddedDoc.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		pdfBytes, err = io.ReadAll(ddc.embeddedDoc)
		if err != nil {
			return err
		}
	}

	ddc.attachments[0] = gofpdf.Attachment{
		Content:     pdfBytes,
		Filename:    ddc.embeddedDocFileName,
		Description: ddc.t("Подлинник электронного документа"),
	}

	for si, signtaure := range ddc.di.Signatures {
		signer := signtaure.SignerName
		if signtaure.SignatureVisualization != nil {
			signer = signtaure.SignatureVisualization.SubjectName
		}

		if signer == "" && signtaure.SignatureVisualization.SubjectID != "" {
			signer = fmt.Sprintf(ddc.t("ИИН %v"), signtaure.SignatureVisualization.SubjectID)
		}

		if signer == "" {
			return errors.New("subject ID not provided")
		}

		if signtaure.FileName == "" {
			return errors.New("signature file name not provided")
		}

		ddc.attachments[1+si] = gofpdf.Attachment{
			Content:     signtaure.Body,
			Filename:    signtaure.FileName,
			Description: fmt.Sprintf(ddc.t("ЭЦП, %v"), signer),
		}
	}

	ddc.pdf.SetAttachments(ddc.attachments)

	if err := ddc.pdf.Error(); err != nil {
		return err
	}

	return nil
}

func (ddc *Builder) constructInfoBlock(visualizeDocument, visualizeSignatures bool, creationDate, builderName, howToVerify string) error {
	ddc.pdf.AddPage()

	ddc.pdf.SetFont(constFontBold, "", 14)
	ddc.pdf.MultiCell(constContentMaxWidth, 10, ddc.t("КАРТОЧКА ЭЛЕКТРОННОГО ДОКУМЕНТА"), "", "CB", false)

	ddc.pdf.SetY(ddc.pdf.GetY() + constPageTopMargin)
	ddc.pdf.SetFont(constFontBold, "", 14)
	ddc.pdf.MultiCell(constContentMaxWidth, 5, ddc.di.Description, "", "CB", false)

	ddc.pdf.SetFont(constFontBold, "", 12)
	{
		ddc.pdf.SetY(ddc.pdf.GetY() + 5)
		y := ddc.pdf.GetY()
		ddc.pdf.MultiCell(constContentMaxWidth/constTwo, 5, ddc.t("Дата и время формирования"), "", "LB", false)
		ddc.pdf.SetY(y)
		ddc.pdf.SetX(constPageLeftMargin + constContentMaxWidth/2)
		ddc.pdf.MultiCell(constContentMaxWidth/constTwo, 5, ddc.t("Информационная система или сервис"), "", "LB", false)
	}

	ddc.pdf.SetFont(constFontRegular, "", 12)
	{
		y := ddc.pdf.GetY()

		ddc.pdf.MultiCell(constContentMaxWidth/constTwo, 5, creationDate, "", "LM", false)
		lowestY := ddc.pdf.GetY()

		ddc.pdf.SetY(y)
		ddc.pdf.SetX(constPageLeftMargin + constContentMaxWidth/2)
		ddc.pdf.MultiCell(constContentMaxWidth/constTwo, 5, builderName, "", "LM", false)

		if lowestY > ddc.pdf.GetY() {
			ddc.pdf.SetY(lowestY)
		}
	}

	// Contents

	ddc.pdf.SetFont(constFontBold, "", 12)
	ddc.pdf.SetY(ddc.pdf.GetY() + 5)
	ddc.pdf.MultiCell(constContentMaxWidth, 5, ddc.t("Содержание:"), "", "LB", false)

	startPage := ddc.infoBlockNumPages + 1
	documentVisualizationPages := "-"
	if visualizeDocument {
		documentVisualizationPages = fmt.Sprintf("%v", startPage)
		startPage += ddc.embeddedPDFNumPages
	}

	signaturesVisualizationPages := "-"
	if visualizeSignatures {
		signaturesVisualizationPages = fmt.Sprintf("%v", startPage)
	}

	ddc.pdf.SetFont(constFontRegular, "", 12)
	{
		y := ddc.pdf.GetY()
		ddc.pdf.MultiCell(constContentMaxWidth-constInfoBlockContentsPageNumColWidth, 5, ddc.t("Информационный блок"), "", "LM", false)
		lowestY := ddc.pdf.GetY()

		ddc.pdf.SetY(y)
		ddc.pdf.SetX(constPageLeftMargin + constContentMaxWidth - constInfoBlockContentsPageNumColWidth)
		ddc.pdf.MultiCell(constInfoBlockContentsPageNumColWidth, 5, "1", "", "RM", false)
		ddc.pdf.SetY(lowestY)

		y = ddc.pdf.GetY()
		ddc.pdf.MultiCell(constContentMaxWidth-constInfoBlockContentsPageNumColWidth, 5, ddc.t("Визуализация электронного документа"), "", "LM", false)
		lowestY = ddc.pdf.GetY()

		ddc.pdf.SetY(y)
		ddc.pdf.SetX(constPageLeftMargin + constContentMaxWidth - constInfoBlockContentsPageNumColWidth)
		ddc.pdf.MultiCell(constInfoBlockContentsPageNumColWidth, 5, documentVisualizationPages, "", "RM", false)
		ddc.pdf.SetY(lowestY)

		y = ddc.pdf.GetY()
		ddc.pdf.MultiCell(constContentMaxWidth-constInfoBlockContentsPageNumColWidth, 5, ddc.t("Визуализация подписей под электронным документом"), "", "LM", false)
		lowestY = ddc.pdf.GetY()

		ddc.pdf.SetY(y)
		ddc.pdf.SetX(constPageLeftMargin + constContentMaxWidth - constInfoBlockContentsPageNumColWidth)
		ddc.pdf.MultiCell(constInfoBlockContentsPageNumColWidth, 5, signaturesVisualizationPages, "", "RM", false)
		ddc.pdf.SetY(lowestY)
	}

	// Attachments

	ddc.pdf.SetFont(constFontBold, "", 12)
	ddc.pdf.CellFormat(constContentMaxWidth, 10, ddc.t("Перечень вложенных файлов:"), "", 1, "LB", false, 0, "")

	ddc.pdf.SetFont(constFontRegular, "", 12)
	for i, a := range ddc.attachments {
		currentY := ddc.pdf.GetY()

		ddc.pdf.MultiCell(constInfoBlockAttachmentsIndexNumColWidth, 5, fmt.Sprintf("%v.", i+1), "", "LM", false)
		newY := ddc.pdf.GetY()
		if newY < currentY { // new page
			currentY = constContentTop
		}

		ddc.pdf.SetY(currentY)
		ddc.pdf.SetX(constPageLeftMargin + constInfoBlockAttachmentsIndexNumColWidth)
		ddc.pdf.MultiCell(constInfoBlockAttachmentsFileNameColWidth, 5, a.Filename, "", "LM", false)
		y := ddc.pdf.GetY()
		if y > newY {
			newY = y
		}

		ddc.pdf.SetY(currentY)
		ddc.pdf.SetX(constPageLeftMargin + constInfoBlockAttachmentsIndexNumColWidth + constInfoBlockAttachmentsFileNameColWidth)
		ddc.pdf.MultiCell(constInfoBlockAttachmentsDescriptionColWidth, 5, a.Description, "", "LM", false)
		y = ddc.pdf.GetY()
		if y > newY || y < currentY { // check if on the new page
			newY = y
		}

		ddc.pdf.SetY(newY)
	}

	// Comments

	infoText := fmt.Sprintf(ddc.t(`
При формировании карточки электронного документа была автоматически выполнена процедура проверки ЭЦП в соответствии с положениями Приказа Министра по инвестициям и развитию Республики Казахстан «Об утверждении Правил проверки подлинности электронной цифровой подписи».

Карточка электронного документа — это файл в формате PDF, состоящий из визуально отображаемой части и вложенных файлов.

Визуально отображаемая часть карточки электронного документа носит исключительно информативный характер и не обладает юридической значимостью.

Многие программы для просмотра PDF поддерживают вложенные файлы, позволяют просматривать их и сохранять как обычные файлы. Среди них Adobe Acrobat Reader и браузер Firefox.

В соответствии с Законом Республики Казахстан «Об электронном документе и электронной цифровой подписи», подлинник электронного документа обладает юридической значимостью в том случае, если он подписан ЭЦП и были выполнены проверки подписи в соответствии с утвержденными правилами.

%v

ВНИМАНИЕ! Остерегайтесь мошенников! При получении электронных документов, обязательно выполняйте проверку подписей! Злоумышленники могут пробовать подделывать или менять визуально отображаемую часть карточки,  так как она не защищена от изменения цифровой подписью.`),
		howToVerify)
	ddc.pdf.SetFont(constFontItalic, "", 10)
	ddc.pdf.MultiCell(constContentMaxWidth, 4, infoText, "", "LT", false)

	// No need for auto page break anymore
	ddc.pdf.SetAutoPageBreak(false, 0)

	// Add header and footer to all Info Block pages
	for i := 1; i <= ddc.pdf.PageCount(); i++ {
		ddc.pdf.SetPage(i)

		if i == 1 {
			err := ddc.addHeaderAndFooterToCurrentPage("", "", false)
			if err != nil {
				return err
			}
		} else {
			err := ddc.addHeaderAndFooterToCurrentPage("", ddc.t("Карточка электронного документа"), true)
			if err != nil {
				return err
			}
		}
	}

	if err := ddc.pdf.Error(); err != nil {
		return err
	}

	return nil
}

func (ddc *Builder) constructDocumentVisualization() error {
	for pageNum := 1; pageNum <= ddc.embeddedPDFNumPages; pageNum++ {
		ddc.pdf.AddPage()

		err := ddc.addHeaderAndFooterToCurrentPage(ddc.t("Визуализация электронного документа"), ddc.t("Карточка электронного документа"), true)
		if err != nil {
			return err
		}

		// Calculate location
		embeddedPageScaledWidth := ddc.embeddedPDFPagesSizes[pageNum-1].Width
		embeddedPageScaledHeight := ddc.embeddedPDFPagesSizes[pageNum-1].Height

		if embeddedPageScaledWidth > constEmbeddedPageMaxWidth {
			embeddedPageScaledHeight = embeddedPageScaledHeight * constEmbeddedPageMaxWidth / embeddedPageScaledWidth
			embeddedPageScaledWidth = constEmbeddedPageMaxWidth
		}

		if embeddedPageScaledHeight > constEmbeddedPageMaxHeight {
			embeddedPageScaledWidth = embeddedPageScaledWidth * constEmbeddedPageMaxHeight / embeddedPageScaledHeight
			embeddedPageScaledHeight = constEmbeddedPageMaxHeight
		}

		xShift := (constEmbeddedPageMaxWidth - embeddedPageScaledWidth) / 2
		if xShift < 0 {
			xShift = 0
		}

		yShift := (constEmbeddedPageMaxHeight - embeddedPageScaledHeight) / 2
		if yShift < 0 {
			yShift = 0
		}

		x := float64(constPageLeftMargin) + xShift
		y := constPageTopMargin + constHeaderHeight + yShift
		w := embeddedPageScaledWidth
		h := embeddedPageScaledHeight

		// Box
		r, g, b := ddc.pdf.GetDrawColor()
		ddc.pdf.SetDrawColor(constGrayR, constGrayG, constGrayB)
		ddc.pdf.Rect(x, y, w, h, "D")
		ddc.pdf.SetDrawColor(r, g, b)

		// Watermark
		r, g, b = ddc.pdf.GetTextColor()
		ddc.pdf.TransformBegin()
		ddc.pdf.TransformRotate(const45ccv, x+w/2, y+h/2)
		ddc.pdf.SetXY(x, y+h/2)
		ddc.pdf.SetTextColor(constGrayR, constGrayG, constGrayB)
		ddc.pdf.SetFont(constFontRegular, "", 20)
		ddc.pdf.SetAlpha(constSemiTransparent, "Normal")
		ddc.pdf.MultiCell(w, 10, ddc.t("ВИЗУАЛИЗАЦИЯ ЭЛЕКТРОННОГО ДОКУМЕНТА"), "", "CM", false)
		ddc.pdf.TransformEnd()
		ddc.pdf.SetTextColor(r, g, b)

		if err := ddc.pdf.Error(); err != nil {
			return err
		}
	}

	return nil
}

func (ddc *Builder) constructSignaturesVisualization() error {
	for sIndex, signatureInfo := range ddc.di.Signatures {
		signature := signatureInfo.SignatureVisualization
		if signature == nil {
			return errors.New("no signature visualization information provided")
		}

		ddc.pdf.AddPage()

		err := ddc.addHeaderAndFooterToCurrentPage(ddc.t("Визуализация электронной цифровой подписи"), ddc.t("Карточка электронного документа"), true)
		if err != nil {
			return err
		}

		// Left column
		ddc.pdf.SetY(constContentTop)

		ddc.pdf.SetFont(constFontBold, "", 10)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 5, fmt.Sprintf(ddc.t("Подпись №%v"), sIndex+1), "", 1, "LB", false, 0, "")

		ddc.pdf.SetFont(constFontRegular, "", 8)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 7, ddc.t("Дата формирования подписи:"), "", 1, "LB", false, 0, "")
		ddc.pdf.SetFont(constFontBold, "", 8)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 5, signature.TSP.GeneratedAt, "", 1, "LB", false, 0, "")

		ddc.pdf.SetFont(constFontRegular, "", 8)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 7, ddc.t("Подписал(а):"), "", 1, "LB", false, 0, "")
		name := fmt.Sprintf(ddc.t("ИИН %v"), signature.SubjectID)
		if signature.SubjectName != "" {
			name = signature.SubjectName + ", " + name
		}
		if signature.SubjectOrgID != "" {
			name = fmt.Sprintf(ddc.t("%v\n%v, БИН %v"), name, signature.SubjectOrgName, signature.SubjectOrgID)
		}
		ddc.pdf.SetFont(constFontBold, "", 8)
		ddc.pdf.MultiCell(constContentLeftColumnWidth, 5, name, "", "LB", false)

		ddc.pdf.SetFont(constFontRegular, "", 8)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 7, ddc.t("Шаблон:"), "", 1, "LB", false, 0, "")
		for _, policyString := range signature.Policies {
			ddc.pdf.SetFont(constFontBold, "", 8)
			ddc.pdf.MultiCell(constContentLeftColumnWidth, 5, fmt.Sprintf("- %v", policyString), "", "LB", false)
		}

		if len(signature.ExtKeyUsage) > 0 || len(signature.KeyUsage) > 0 {
			ddc.pdf.SetFont(constFontRegular, "", 8)
			ddc.pdf.CellFormat(constContentLeftColumnWidth, 7, ddc.t("Допустимое использование:"), "", 1, "LB", false, 0, "")
			ddc.pdf.SetFont(constFontBold, "", 8)
			for _, keyUsage := range signature.KeyUsage {
				ddc.pdf.MultiCell(constContentLeftColumnWidth, 5, fmt.Sprintf("- %v", keyUsage), "", "LB", false)
			}
			for _, extKeyUsage := range signature.ExtKeyUsage {
				ddc.pdf.MultiCell(constContentLeftColumnWidth, 5, fmt.Sprintf("- %v", extKeyUsage), "", "LB", false)
			}
		}

		textBottom := ddc.pdf.GetY()

		// Right column
		ddc.pdf.SetY(constContentTop)

		ddc.pdf.SetX(constContentRightColumnX)
		ddc.pdf.SetFont(constFontRegular, "", 6)
		r, g, b := ddc.pdf.GetDrawColor()
		ddc.pdf.SetDrawColor(constGrayR, constGrayG, constGrayB)
		certificateDetailsText := fmt.Sprintf(ddc.t(`Субъект: %v
Альтернативные имена: %v
Серийный номер: %v
С: %v
По: %v
Издатель: %v`), signature.Subject, signature.SubjectAltName, signature.SerialNumber, signature.From, signature.Until, signature.Issuer)
		ddc.pdf.MultiCell(constContentRightColumnWidth, 3, certificateDetailsText, "1", "LM", false)
		ddc.pdf.SetDrawColor(r, g, b)
		ddc.pdf.SetY(ddc.pdf.GetY() + 1)

		ddc.pdf.SetX(constContentRightColumnX)
		ddc.pdf.SetFont(constFontRegular, "", 6)
		r, g, b = ddc.pdf.GetDrawColor()
		ddc.pdf.SetDrawColor(constGrayR, constGrayG, constGrayB)
		tspDetailsText := fmt.Sprintf(ddc.t(`Метка времени: %v
Субъект: %v
Серийный номер: %v
Издатель: %v`), signature.TSP.GeneratedAt, signature.TSP.Subject, signature.TSP.SerialNumber, signature.TSP.Issuer)
		ddc.pdf.MultiCell(constContentRightColumnWidth, 3, tspDetailsText, "1", "LM", false)
		ddc.pdf.SetDrawColor(r, g, b)
		ddc.pdf.SetY(ddc.pdf.GetY() + 1)

		ddc.pdf.SetX(constContentRightColumnX)
		ddc.pdf.SetFont(constFontRegular, "", 6)
		r, g, b = ddc.pdf.GetDrawColor()
		ddc.pdf.SetDrawColor(constGrayR, constGrayG, constGrayB)
		ocspDetailsText := fmt.Sprintf(ddc.t(`OCSP: %v
Сформирован: %v
Субъект: %v
Серийный номер: %v
Издатель: %v`), signature.OCSP.CertStatus, signature.OCSP.GeneratedAt, signature.OCSP.Subject, signature.OCSP.SerialNumber, signature.OCSP.Issuer)
		ddc.pdf.MultiCell(constContentRightColumnWidth, 3, ocspDetailsText, "1", "LM", false)
		ddc.pdf.SetDrawColor(r, g, b)
		ddc.pdf.SetY(ddc.pdf.GetY() + 1)

		secondTextBottom := ddc.pdf.GetY()
		if secondTextBottom > textBottom {
			textBottom = secondTextBottom
		}

		// QR codes

		yQR := textBottom + constSignatureQRCodeTopMargin + constSignatureQRCodeMargin
		qrCodesInARow := 0
		for qrIndex, qr := range signature.QRCodes {
			imgOptions := gofpdf.ImageOptions{
				ReadDpi:   true,
				ImageType: "png",
			}
			fileName := fmt.Sprintf("qr-%v-%v.png", signatureInfo.FileName, qrIndex)
			ddc.pdf.RegisterImageOptionsReader(fileName, imgOptions, bytes.NewReader(qr))

			x := constPageLeftMargin + constSignatureQRCodeMargin*(qrCodesInARow+1) + constSignatureQRCodeImageSize*qrCodesInARow
			ddc.pdf.ImageOptions(fileName, float64(x), yQR, constSignatureQRCodeImageSize, constSignatureQRCodeImageSize, false, imgOptions, 0, "")

			qrCodesInARow++
			if qrCodesInARow == constSignatureQRCodesInARow {
				qrCodesInARow = 0
				yQR += constSignatureQRCodeMargin + constSignatureQRCodeImageSize
			}
		}

		if err := ddc.pdf.Error(); err != nil {
			return err
		}
	}

	return nil
}

func (ddc *Builder) t(input string) string {
	if ddc.di.Language == "kk" {
		output, ok := kk[input]
		if ok {
			return output
		}
	}

	if ddc.di.Language == "kk/ru" {
		output, ok := kkRU[input]
		if ok {
			return output
		}
	}

	return input
}

// AttachedFile information
type AttachedFile struct {
	Name  string
	Bytes []byte
}

// ExtractAttachments from DDC and return them as structures
func ExtractAttachments(ddcPdf io.ReadSeeker) (documentOriginal *AttachedFile, signatures []AttachedFile, err error) {
	attachments, err := pdfcpuapi.ExtractAttachmentsRaw(ddcPdf, "", nil, nil)
	if err != nil {
		return nil, nil, err
	}

	if len(attachments) < constMinimalAttachmentsDuringExport {
		return nil, nil, fmt.Errorf("PDF contains less than %v attachments (%v)", len(attachments), constMinimalAttachmentsDuringExport)
	}

	documentOriginalBytes, err := io.ReadAll(attachments[0].Reader)
	if err != nil {
		return nil, nil, err
	}

	documentOriginal = &AttachedFile{
		Name:  attachments[0].FileName,
		Bytes: documentOriginalBytes,
	}

	attachments = attachments[1:]

	signatures = make([]AttachedFile, len(attachments))

	for i := 0; i < len(attachments); i++ {
		signatureBytes, readErr := io.ReadAll(attachments[i].Reader)
		if readErr != nil {
			return nil, nil, readErr
		}

		signatures[i].Name = attachments[i].FileName
		signatures[i].Bytes = signatureBytes
	}

	return documentOriginal, signatures, nil
}
