package ddc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/phpdave11/gofpdf"
	"github.com/phpdave11/gofpdf/contrib/gofpdi"
	realgofpdi "github.com/phpdave11/gofpdi"
)

const (
	constPageType                = "A4"
	constPageOrientation         = "P"
	constPageUnits               = "mm"
	constPageWidth               = 210
	constPageHeight              = 297
	constPageTopMargin           = 10
	constPageBottomMargin        = 10
	constPageLeftMargin          = 30
	constPageRightMargin         = 10
	constContentMaxWidth         = constPageWidth - constPageLeftMargin - constPageRightMargin
	constContentMaxHeight        = constPageHeight - constPageTopMargin - constPageBottomMargin
	constHeaderHeight            = 10
	constFooterHeight            = 10
	constEmbeddedPageMaxWidth    = constContentMaxWidth
	constEmbeddedPageMaxHeight   = constContentMaxHeight - constHeaderHeight - constFooterHeight
	constContentTop              = constPageTopMargin + constHeaderHeight + 10
	constContentLeftColumnWidth  = constContentMaxWidth / 3 * 2
	constContentRightColumnWidth = constContentMaxWidth / 3
	constContentRightColumnX     = constPageLeftMargin + constContentLeftColumnWidth

	constSignatureQRCodeImageSize = 42
	constSignatureQRCodesInARow   = 4
	constSignatureQRCodeMargin    = (constContentMaxWidth - constSignatureQRCodeImageSize*constSignatureQRCodesInARow) / (constSignatureQRCodesInARow + 2)
	constSignatureQRCodeTopMargin = 5

	constInfoBlockContentsPageNumColWidth        = 10
	constInfoBlockAttachmentsIndexNumColWidth    = 10
	constInfoBlockAttachmentsDescriptionColWidth = 75
	constInfoBlockAttachmentsFileNameColWidth    = constContentMaxWidth - constInfoBlockAttachmentsIndexNumColWidth - constInfoBlockAttachmentsDescriptionColWidth

	constPDFBoxType = "/MediaBox"

	constFontRegular    = "LiberationSans-Regular"
	constFontBold       = "LiberationSans-Bold"
	constFontItalic     = "LiberationSans-Italic"
	constFontBoldItalic = "LiberationSans-BoldItalic"

	const45ccv = 45

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

	// Subjects full RDN in RFC 4514 format (optional)
	Subject string `json:"subject"`

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

	// File name for attachement
	FileName string `json:"fileName"`

	// Signer name to build attachement description (optional, required if SignatureVisualization is not provided)
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

	// Signatures information
	Signatures []SignatureInfo `json:"signatures"`
}

// Builder builds Digital Document Card
type Builder struct {
	pdf          *gofpdf.Fpdf
	imageOptions gofpdf.ImageOptions
	di           DocumentInfo

	attachments []gofpdf.Attachment

	infoBlockNumPages int

	embeddedPDF           io.ReadSeeker
	embeddedPDFFileName   string
	embeddedPDFNumPages   int
	embeddedPDFPagesSizes map[int]map[string]map[string]float64

	totalPages int
}

// NewBuilder creates a new DDC Builder
func NewBuilder(di DocumentInfo) (*Builder, error) {
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
	// Validate PDF via pdfcpu because gopdfi Importer does not return errors and panics
	err := pdfcpuapi.Validate(pdf, nil)
	if err != nil {
		return err
	}

	_, err = pdf.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	imp := realgofpdi.NewImporter()
	imp.SetSourceStream(&pdf)
	numPages := imp.GetNumPages()
	pageSizes := imp.GetPageSizes()

	if numPages < 1 {
		return errors.New("document is empty")
	}

	_, err = pdf.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	ddc.embeddedPDF = pdf
	ddc.embeddedPDFFileName = fileName
	ddc.embeddedPDFNumPages = numPages
	ddc.embeddedPDFPagesSizes = pageSizes

	return nil
}

func (ddc *Builder) initPdf() (pdf *gofpdf.Fpdf, err error) {
	pdf = gofpdf.New(constPageOrientation, constPageUnits, constPageType, "")

	// Fpdf by default sets PDF version to "1.3" and not always bumps it when uses newer features.
	// Adding an empty layer bumps the version to "1.5" thus increasing compliance with the standard.
	pdf.AddLayer("Empty", false)

	pdf.AddUTF8FontFromBytes(constFontRegular, "", embeddedFontRegular)
	pdf.AddUTF8FontFromBytes(constFontBold, "", embeddedFontBold)
	pdf.AddUTF8FontFromBytes(constFontItalic, "", embeddedFontItalic)
	pdf.AddUTF8FontFromBytes(constFontBoldItalic, "", embeddedFontBoldItalic)

	// Fpdf margins are used only on Info Block pages, configure them with header and footer height to utilize auto page break
	pdf.SetMargins(constPageLeftMargin, constPageTopMargin+constHeaderHeight, constPageRightMargin)
	pdf.SetAutoPageBreak(true, constPageBottomMargin+constFooterHeight)

	if err := pdf.Error(); err != nil {
		return nil, err
	}

	return pdf, nil
}

func (ddc *Builder) addHeaderAndFooterToCurrentPage(headerText, footerText string, addPageNumber bool) error {
	ddc.pdf.Line(constPageLeftMargin, constPageTopMargin+constHeaderHeight, constPageLeftMargin+constContentMaxWidth, constPageTopMargin+constHeaderHeight)

	if headerText != "" {
		ddc.pdf.SetXY(constPageLeftMargin, constPageTopMargin)
		ddc.pdf.SetFont(constFontRegular, "", 11)
		ddc.pdf.CellFormat(constContentMaxWidth, constHeaderHeight, headerText, "", 1, "CM", false, 0, "")
	}

	ddc.pdf.Line(constPageLeftMargin, constPageHeight-constPageBottomMargin-constFooterHeight, constPageLeftMargin+constContentMaxWidth, constPageHeight-constPageBottomMargin-constFooterHeight)

	if footerText != "" {
		ddc.pdf.SetXY(constPageLeftMargin, constPageHeight-constPageBottomMargin-constFooterHeight)
		ddc.pdf.SetFont(constFontRegular, "", 11)
		ddc.pdf.CellFormat(constContentMaxWidth, constFooterHeight, footerText, "", 1, "LM", false, 0, "")
	}

	if addPageNumber {
		ddc.pdf.SetXY(constPageLeftMargin, constPageHeight-constPageBottomMargin-constFooterHeight)
		ddc.pdf.SetFont(constFontRegular, "", 11)
		pageNumberText := fmt.Sprintf("стр. %v из %v", ddc.pdf.PageNo(), ddc.totalPages)
		ddc.pdf.CellFormat(constContentMaxWidth, constFooterHeight, pageNumberText, "", 1, "RM", false, 0, "")
	}

	if err := ddc.pdf.Error(); err != nil {
		return err
	}

	return nil
}

// Build DDC and write it's bytes to w
func (ddc *Builder) Build(visualizeDocument, visualizeSignatures bool, creationDate, builderName, howToVerify string, w io.Writer) error {
	var err error

	// PDF init
	ddc.pdf, err = ddc.initPdf()
	if err != nil {
		return err
	}

	// Attachments
	err = ddc.attachFiles()
	if err != nil {
		return err
	}

	// Simulate Info Block to find out how many pages it'll take
	tempDDC, err := NewBuilder(ddc.di)
	if err != nil {
		return err
	}

	err = tempDDC.EmbedPDF(ddc.embeddedPDF, ddc.embeddedPDFFileName)
	if err != nil {
		return err
	}

	tempDDC.pdf, err = tempDDC.initPdf()
	if err != nil {
		return err
	}

	err = tempDDC.attachFiles()
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
	err = ddc.pdf.Output(w)
	if err != nil {
		return err
	}

	// Just in case
	if err := ddc.pdf.Error(); err != nil {
		return err
	}

	return nil
}

func (ddc *Builder) attachFiles() error {
	ddc.attachments = make([]gofpdf.Attachment, len(ddc.di.Signatures)+1)

	_, err := ddc.embeddedPDF.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	pdfBytes, err := io.ReadAll(ddc.embeddedPDF)
	if err != nil {
		return err
	}

	ddc.attachments[0] = gofpdf.Attachment{
		Content:     pdfBytes,
		Filename:    ddc.embeddedPDFFileName,
		Description: "Подлинник электронного документа",
	}

	for si, signtaure := range ddc.di.Signatures {
		signer := signtaure.SignerName
		if signtaure.SignatureVisualization != nil {
			signer = signtaure.SignatureVisualization.SubjectName
		}

		if signer == "" {
			return errors.New("signer name not provided")
		}

		if signtaure.FileName == "" {
			return errors.New("signature file name not provided")
		}

		ddc.attachments[1+si] = gofpdf.Attachment{
			Content:     signtaure.Body,
			Filename:    signtaure.FileName,
			Description: fmt.Sprintf("ЭЦП, %v", signer),
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
	ddc.pdf.CellFormat(constContentMaxWidth, 10, "КАРТОЧКА ЭЛЕКТРОННОГО ДОКУМЕНТА", "", 1, "CB", false, 0, "")

	ddc.pdf.SetY(ddc.pdf.GetY() + constPageTopMargin)
	ddc.pdf.SetFont(constFontBold, "", 14)
	ddc.pdf.MultiCell(constContentMaxWidth, 5, ddc.di.Description, "", "CB", false)

	ddc.pdf.SetFont(constFontBold, "", 12)
	ddc.pdf.CellFormat(constContentMaxWidth/constTwo, 10, "Дата и время формирования", "", 0, "LB", false, 0, "")
	ddc.pdf.CellFormat(constContentMaxWidth/constTwo, 10, "Информационная система или сервис", "", 1, "LB", false, 0, "")

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
	ddc.pdf.CellFormat(constContentMaxWidth, 10, "Содержание:", "", 1, "LB", false, 0, "")

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
	ddc.pdf.CellFormat(constContentMaxWidth-constInfoBlockContentsPageNumColWidth, 5, "Информационный блок", "", 0, "LM", false, 0, "")
	ddc.pdf.CellFormat(constInfoBlockContentsPageNumColWidth, 5, "1", "", 1, "LM", false, 0, "")
	ddc.pdf.CellFormat(constContentMaxWidth-constInfoBlockContentsPageNumColWidth, 5, "Визуализация электронного документа", "", 0, "LM", false, 0, "")
	ddc.pdf.CellFormat(constInfoBlockContentsPageNumColWidth, 5, documentVisualizationPages, "", 1, "LM", false, 0, "")
	ddc.pdf.CellFormat(constContentMaxWidth-constInfoBlockContentsPageNumColWidth, 5, "Визуализация подписей под электронным документом", "", 0, "LM", false, 0, "")
	ddc.pdf.CellFormat(constInfoBlockContentsPageNumColWidth, 5, signaturesVisualizationPages, "", 1, "LM", false, 0, "")

	// Attachments

	ddc.pdf.SetFont(constFontBold, "", 12)
	ddc.pdf.CellFormat(constContentMaxWidth, 10, "Перечень вложенных файлов:", "", 1, "LB", false, 0, "")

	ddc.pdf.SetFont(constFontRegular, "", 12)
	for i, a := range ddc.attachments {
		y := ddc.pdf.GetY()

		ddc.pdf.MultiCell(constInfoBlockAttachmentsIndexNumColWidth, 5, fmt.Sprintf("%v.", i+1), "", "LM", false)
		lowestY := ddc.pdf.GetY()

		ddc.pdf.SetY(y)
		ddc.pdf.SetX(constPageLeftMargin + constInfoBlockAttachmentsIndexNumColWidth)
		ddc.pdf.MultiCell(constInfoBlockAttachmentsFileNameColWidth, 5, a.Filename, "", "LM", false)
		if ddc.pdf.GetY() > lowestY {
			lowestY = ddc.pdf.GetY()
		}

		ddc.pdf.SetY(y)
		ddc.pdf.SetX(constPageLeftMargin + constInfoBlockAttachmentsIndexNumColWidth + constInfoBlockAttachmentsFileNameColWidth)
		ddc.pdf.MultiCell(constInfoBlockAttachmentsDescriptionColWidth, 5, a.Description, "", "LM", false)
		if ddc.pdf.GetY() > lowestY {
			lowestY = ddc.pdf.GetY()
		}

		ddc.pdf.SetY(lowestY)
	}

	// Comments

	infoText := fmt.Sprintf(`
При формировании карточки электронного документа была автоматически выполнена процедура проверки ЭЦП в соответствии с положениями Приказа Министра по инвестициям и развитию Республики Казахстан «Об утверждении Правил проверки подлинности электронной цифровой подписи».

Карточка электронного документа — это файл в формате PDF, состоящий из визуально отображаемой части и вложенных файлов.

Визуально отображаемая часть карточки электронного документа носит исключительно информативный характер и не обладает юридической значимостью.

Многие программы для просмотра PDF поддерживают вложенные файлы, позволяют просматривать их и сохранять как обычные файлы. Среди них Adobe Acrobat Reader и браузер Firefox.

В соответствии с Законом Республики Казахстан «Об электронном документе и электронной цифровой подписи», подлинник электронного документа обладает юридической значимостью в том случае, если он подписан ЭЦП и были выполнены проверки подписи в соответствии с утвержденными правилами.

%v

ВНИМАНИЕ! Остерегайтесь мошенников! При получении электронных документов, обязательно выполняйте проверку подписей! Злоумышленники могут пробовать подделывать или менять визуально отображаемую часть карточки,  так как она не защищена от изменения цифровой подписью.`,
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
			err := ddc.addHeaderAndFooterToCurrentPage("", "Карточка электронного документа", true)
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
	imp := gofpdi.NewImporter()
	for pageNum := 1; pageNum <= ddc.embeddedPDFNumPages; pageNum++ {
		ddc.pdf.AddPage()

		err := ddc.addHeaderAndFooterToCurrentPage("Визуализация электронного документа", "Карточка электронного документа", true)
		if err != nil {
			return err
		}

		// Calculate location
		embeddedPageSize := ddc.embeddedPDFPagesSizes[pageNum][constPDFBoxType]
		embeddedPageScaledWidth := embeddedPageSize["w"]
		embeddedPageScaledHeight := embeddedPageSize["h"]

		if embeddedPageScaledWidth > constEmbeddedPageMaxWidth {
			embeddedPageScaledHeight = embeddedPageScaledHeight * constEmbeddedPageMaxWidth / embeddedPageScaledWidth
			embeddedPageScaledWidth = constEmbeddedPageMaxWidth
		}

		if embeddedPageScaledHeight > constEmbeddedPageMaxHeight {
			embeddedPageScaledWidth = embeddedPageScaledWidth * constEmbeddedPageMaxHeight / embeddedPageScaledHeight
			embeddedPageScaledHeight = constEmbeddedPageMaxHeight
		}

		yShift := (constEmbeddedPageMaxHeight - embeddedPageScaledHeight) / 2
		if yShift < 0 {
			yShift = 0
		}

		x := float64(constPageLeftMargin)
		y := constPageTopMargin + constHeaderHeight + yShift
		w := embeddedPageScaledWidth
		h := embeddedPageScaledHeight

		r, g, b := ddc.pdf.GetDrawColor()
		ddc.pdf.SetDrawColor(constGrayR, constGrayG, constGrayB)
		ddc.pdf.Rect(x, y, w, h, "D")
		ddc.pdf.SetDrawColor(r, g, b)

		_, err = ddc.embeddedPDF.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		tpl := imp.ImportPageFromStream(ddc.pdf, &ddc.embeddedPDF, pageNum, constPDFBoxType)
		imp.UseImportedTemplate(ddc.pdf, tpl, x, y, w, h)

		// Watermark
		r, g, b = ddc.pdf.GetTextColor()
		ddc.pdf.TransformBegin()
		ddc.pdf.TransformRotate(const45ccv, x+w/2, y+h/2)
		ddc.pdf.SetXY(x, y)
		ddc.pdf.SetTextColor(constGrayR, constGrayG, constGrayB)
		ddc.pdf.SetFont(constFontRegular, "", 40)
		ddc.pdf.SetAlpha(constSemiTransparent, "Normal")
		ddc.pdf.CellFormat(w, h, "Копия электронного документа", "", 1, "CM", false, 0, "")
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

		err := ddc.addHeaderAndFooterToCurrentPage("Визуализация электронной цифровой подписи", "Карточка электронного документа", true)
		if err != nil {
			return err
		}

		// Left column
		ddc.pdf.SetY(constContentTop)

		ddc.pdf.SetFont(constFontBold, "", 10)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 5, fmt.Sprintf("Подпись №%v", sIndex+1), "", 1, "LB", false, 0, "")

		ddc.pdf.SetFont(constFontRegular, "", 8)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 8, "Дата формирования подписи:", "", 1, "LB", false, 0, "")
		ddc.pdf.SetFont(constFontBold, "", 10)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 5, signature.TSP.GeneratedAt, "", 1, "LB", false, 0, "")

		name := fmt.Sprintf("%v, ИИН %v", signature.SubjectName, signature.SubjectID)
		ddc.pdf.SetFont(constFontRegular, "", 8)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 8, "Подписал(а):", "", 1, "LB", false, 0, "")
		ddc.pdf.SetFont(constFontBold, "", 10)
		ddc.pdf.MultiCell(constContentLeftColumnWidth, 5, name, "", "LB", false)

		ddc.pdf.SetFont(constFontRegular, "", 8)
		ddc.pdf.CellFormat(constContentLeftColumnWidth, 8, "Шаблон:", "", 1, "LB", false, 0, "")
		for _, policyString := range signature.Policies {
			ddc.pdf.SetFont(constFontBold, "", 10)
			ddc.pdf.CellFormat(constContentLeftColumnWidth, 5, policyString, "", 1, "LB", false, 0, "")
		}

		if signature.SubjectOrgID != "" {
			orgName := fmt.Sprintf("%v, БИН %v", signature.SubjectOrgName, signature.SubjectOrgID)
			ddc.pdf.SetFont(constFontRegular, "", 8)
			ddc.pdf.CellFormat(constContentLeftColumnWidth, 8, "Представляет организацию:", "", 1, "LB", false, 0, "")
			ddc.pdf.SetFont(constFontBold, "", 10)
			ddc.pdf.MultiCell(constContentLeftColumnWidth, 5, orgName, "", "LB", false)
		}

		if len(signature.ExtKeyUsage) > 0 || len(signature.KeyUsage) > 0 {
			ddc.pdf.SetFont(constFontRegular, "", 8)
			ddc.pdf.CellFormat(constContentLeftColumnWidth, 8, "Допустимое использование:", "", 1, "LB", false, 0, "")
			ddc.pdf.SetFont(constFontBold, "", 10)
			for _, keyUsage := range signature.KeyUsage {
				ddc.pdf.CellFormat(constContentLeftColumnWidth, 5, keyUsage, "", 1, "LB", false, 0, "")
			}
			for _, extKeyUsage := range signature.ExtKeyUsage {
				ddc.pdf.CellFormat(constContentLeftColumnWidth, 5, extKeyUsage, "", 1, "LB", false, 0, "")
			}
		}

		textBottom := ddc.pdf.GetY()

		// Right column
		ddc.pdf.SetY(constContentTop)

		ddc.pdf.SetX(constContentRightColumnX)
		ddc.pdf.SetFont(constFontRegular, "", 6)
		r, g, b := ddc.pdf.GetDrawColor()
		ddc.pdf.SetDrawColor(constGrayR, constGrayG, constGrayB)
		certificateDetailsText := fmt.Sprintf(`Субъект: %v
Серийный номер: %v
С: %v
По: %v
Издатель: %v`, signature.Subject, signature.SerialNumber, signature.From, signature.Until, signature.Issuer)
		ddc.pdf.MultiCell(constContentRightColumnWidth, 3, certificateDetailsText, "1", "LM", false)
		ddc.pdf.SetDrawColor(r, g, b)
		ddc.pdf.SetY(ddc.pdf.GetY() + 1)

		ddc.pdf.SetX(constContentRightColumnX)
		ddc.pdf.SetFont(constFontRegular, "", 6)
		r, g, b = ddc.pdf.GetDrawColor()
		ddc.pdf.SetDrawColor(constGrayR, constGrayG, constGrayB)
		tspDetailsText := fmt.Sprintf(`Метка времени: %v
Субъект: %v
Серийный номер: %v
Издатель: %v`, signature.TSP.GeneratedAt, signature.TSP.Subject, signature.TSP.SerialNumber, signature.TSP.Issuer)
		ddc.pdf.MultiCell(constContentRightColumnWidth, 3, tspDetailsText, "1", "LM", false)
		ddc.pdf.SetDrawColor(r, g, b)
		ddc.pdf.SetY(ddc.pdf.GetY() + 1)

		ddc.pdf.SetX(constContentRightColumnX)
		ddc.pdf.SetFont(constFontRegular, "", 6)
		r, g, b = ddc.pdf.GetDrawColor()
		ddc.pdf.SetDrawColor(constGrayR, constGrayG, constGrayB)
		ocspDetailsText := fmt.Sprintf(`OCSP: %v
Сформирован: %v
Субъект: %v
Серийный номер: %v
Издатель: %v`, signature.OCSP.CertStatus, signature.OCSP.GeneratedAt, signature.OCSP.Subject, signature.OCSP.SerialNumber, signature.OCSP.Issuer)
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

// AttachedFile information
type AttachedFile struct {
	Name  string
	Bytes []byte
}

// ExtractAttachments from DDC and return them as structures
func ExtractAttachments(ddcPdf io.ReadSeeker) (documentOriginal *AttachedFile, signatures []AttachedFile, err error) {
	err = pdfcpuapi.Validate(ddcPdf, nil)
	if err != nil {
		return nil, nil, err
	}

	attachments, err := pdfcpuapi.ExtractAttachmentsRaw(ddcPdf, "", nil, nil)
	if err != nil {
		return nil, nil, err
	}

	if len(attachments) < constMinimalAttachmentsDuringExport {
		return nil, nil, fmt.Errorf("PDF contains less than %v attachments (%v)", len(attachments), constMinimalAttachmentsDuringExport)
	}

	documentOriginalBytes, err := ioutil.ReadAll(attachments[0].Reader)
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
		signatureBytes, readErr := ioutil.ReadAll(attachments[i].Reader)
		if readErr != nil {
			return nil, nil, readErr
		}

		signatures[i].Name = attachments[i].FileName
		signatures[i].Bytes = signatureBytes
	}

	return documentOriginal, signatures, nil
}
