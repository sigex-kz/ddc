package ddc

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
)

const (
	consthowToVerifyString = "Для того, чтобы выполнить проверку подписи, перейдите по ссылке https://sigex.kz/ и перетащите этот файл в область Найти документ (либо кликните на область Найти документ и выберите файл в диалоговом окне). Сервис извлечет вложенные файлы, найдет страницу подписанного документа, сравнит подписи в системе и файле и выполнит их проверку. Так же сервис предоставит возможность скачать извлеченный подлинник электронного документа."
)

func TestPingPongFullFeatured(t *testing.T) {
	// Build

	jsonBytes, err := os.ReadFile("./tests-data/fullfeatured-di.json")
	if err != nil {
		t.Fatal(err)
	}

	di := DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		t.Fatal(err)
	}

	ddc, err := NewBuilder(&di)
	if err != nil {
		t.Fatal(err)
	}

	pdf, err := os.Open("./tests-data/embed.pdf")
	if err != nil {
		t.Fatal(err)
	}

	err = ddc.EmbedPDF(pdf, di.Title)
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	err = ddc.Build(true, true, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/fullfeatured.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// Extract and check

	doc, signatures, err := ExtractAttachments(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	if doc.Name != di.Title {
		t.Fatalf("unexpected document file name (%v)", doc.Name)
	}

	_, err = pdf.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatal(err)
	}
	pdfBytes, err := io.ReadAll(pdf)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(doc.Bytes, pdfBytes) {
		t.Fatalf("unexpected document contents (%v) (%v)", len(doc.Bytes), len(pdfBytes))
	}

	if len(signatures) != len(di.Signatures) {
		t.Fatalf("quantity of extracted signatures (%v) does not match the original (%v)", len(signatures), len(di.Signatures))
	}

	for i := 0; i < len(signatures); i++ {
		if signatures[i].Name != di.Signatures[i].FileName {
			t.Fatalf("unexpected signature file name (%v), expected (%v)", signatures[i].Name, di.Signatures[i].FileName)
		}

		if !bytes.Equal(signatures[i].Bytes, di.Signatures[i].Body) {
			t.Fatalf("unexpected signature contents (%v)", signatures[i].Name)
		}
	}
}

func TestPingPongNonPDFDocument(t *testing.T) {
	// Build

	jsonBytes, err := os.ReadFile("./tests-data/fullfeatured-di.json")
	if err != nil {
		t.Fatal(err)
	}

	di := DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		t.Fatal(err)
	}
	di.Title = "embed.txt"

	ddc, err := NewBuilder(&di)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := os.Open("./tests-data/embed.txt")
	if err != nil {
		t.Fatal(err)
	}

	err = ddc.EmbedDoc(doc, di.Title)
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer

	err = ddc.Build(true, true, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err == nil {
		t.Fatal("should fail")
	}

	err = ddc.Build(false, true, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/non-pdf.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// Extract and check

	docExtracted, signatures, err := ExtractAttachments(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	if docExtracted.Name != di.Title {
		t.Fatalf("unexpected document file name (%v)", docExtracted.Name)
	}

	_, err = doc.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatal(err)
	}
	pdfBytes, err := io.ReadAll(doc)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(docExtracted.Bytes, pdfBytes) {
		t.Fatalf("unexpected document contents (%v) (%v)", len(docExtracted.Bytes), len(pdfBytes))
	}

	if len(signatures) != len(di.Signatures) {
		t.Fatalf("quantity of extracted signatures (%v) does not match the original (%v)", len(signatures), len(di.Signatures))
	}

	for i := 0; i < len(signatures); i++ {
		if signatures[i].Name != di.Signatures[i].FileName {
			t.Fatalf("unexpected signature file name (%v), expected (%v)", signatures[i].Name, di.Signatures[i].FileName)
		}

		if !bytes.Equal(signatures[i].Bytes, di.Signatures[i].Body) {
			t.Fatalf("unexpected signature contents (%v)", signatures[i].Name)
		}
	}
}

func TestBuildPartialVisualizations(t *testing.T) {
	// Build

	jsonBytes, err := os.ReadFile("./tests-data/fullfeatured-di.json")
	if err != nil {
		t.Fatal(err)
	}

	di := DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		t.Fatal(err)
	}

	ddc, err := NewBuilder(&di)
	if err != nil {
		t.Fatal(err)
	}

	pdf, err := os.Open("./tests-data/embed.pdf")
	if err != nil {
		t.Fatal(err)
	}

	err = ddc.EmbedPDF(pdf, di.Title)
	if err != nil {
		t.Fatal(err)
	}

	// Only document visualization
	var b bytes.Buffer
	err = ddc.Build(true, false, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/only-doc-vis.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// Only signatures visualization
	b.Reset()
	err = ddc.Build(false, true, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/only-sig-vis.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	// No visualizations
	b.Reset()
	err = ddc.Build(false, false, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/no-vis.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuildNoQRCodes(t *testing.T) {
	// Build

	jsonBytes, err := os.ReadFile("./tests-data/fullfeatured-di.json")
	if err != nil {
		t.Fatal(err)
	}

	di := DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(di.Signatures); i++ {
		di.Signatures[i].SignatureVisualization.QRCodes = nil
	}

	ddc, err := NewBuilder(&di)
	if err != nil {
		t.Fatal(err)
	}

	pdf, err := os.Open("./tests-data/embed.pdf")
	if err != nil {
		t.Fatal(err)
	}

	err = ddc.EmbedPDF(pdf, di.Title)
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	err = ddc.Build(true, true, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/no-qr-codes.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuildLongStrings(t *testing.T) {
	// Build

	jsonBytes, err := os.ReadFile("./tests-data/lognstrings-di.json")
	if err != nil {
		t.Fatal(err)
	}

	di := DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		t.Fatal(err)
	}

	ddc, err := NewBuilder(&di)
	if err != nil {
		t.Fatal(err)
	}

	pdf, err := os.Open("./tests-data/embed.pdf")
	if err != nil {
		t.Fatal(err)
	}

	err = ddc.EmbedPDF(pdf, "fullfeatured-embed ревизия документа 2020.02.20.pdf")
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	err = ddc.Build(true, true, "2021.01.01 13:45:00 UTC+6", "сервис формирования карточек электронных документов", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/longnames.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuildNoID(t *testing.T) {
	// Build

	jsonBytes, err := os.ReadFile("./tests-data/fullfeatured-di.json")
	if err != nil {
		t.Fatal(err)
	}

	di := DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		t.Fatal(err)
	}

	di.ID = ""
	di.IDQRCode = nil

	ddc, err := NewBuilder(&di)
	if err != nil {
		t.Fatal(err)
	}

	pdf, err := os.Open("./tests-data/embed.pdf")
	if err != nil {
		t.Fatal(err)
	}

	err = ddc.EmbedPDF(pdf, di.Title)
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	err = ddc.Build(true, true, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/no-id.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuildKK(t *testing.T) {
	// Build

	jsonBytes, err := os.ReadFile("./tests-data/fullfeatured-di.json")
	if err != nil {
		t.Fatal(err)
	}

	di := DocumentInfo{}
	err = json.Unmarshal(jsonBytes, &di)
	if err != nil {
		t.Fatal(err)
	}

	di.Language = "kk"

	ddc, err := NewBuilder(&di)
	if err != nil {
		t.Fatal(err)
	}

	pdf, err := os.Open("./tests-data/embed.pdf")
	if err != nil {
		t.Fatal(err)
	}

	err = ddc.EmbedPDF(pdf, di.Title)
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	err = ddc.Build(true, true, "2021.01.01 13:45:00 UTC+6", "ddc test builder", consthowToVerifyString, &b)
	if err != nil {
		t.Fatal(err)
	}

	err = pdfcpuapi.Validate(bytes.NewReader(b.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile("./tests-output/kk.pdf", b.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}
