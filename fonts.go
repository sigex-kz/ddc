package ddc

import (
	// To embed fonts
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed fonts/LiberationSans-Regular.ttf
var embeddedFontRegular []byte

//go:embed fonts/LiberationSans-Bold.ttf
var embeddedFontBold []byte

//go:embed fonts/LiberationSans-Italic.ttf
var embeddedFontItalic []byte

//go:embed fonts/LiberationSans-BoldItalic.ttf
var embeddedFontBoldItalic []byte

func extractEmbeddedFonts() (fontsDir string, err error) {
	fontsDir, err = os.MkdirTemp("", "ddc-fonts")
	if err != nil {
		return "", err
	}

	buildFontFilePath := func(dir, name string) string {
		return filepath.Join(dir, name+".ttf")
	}

	if err := os.WriteFile(buildFontFilePath(fontsDir, constFontRegular), embeddedFontRegular, 0600); err != nil {
		return "", err
	}

	if err := os.WriteFile(buildFontFilePath(fontsDir, constFontBold), embeddedFontBold, 0600); err != nil {
		return "", err
	}

	if err := os.WriteFile(buildFontFilePath(fontsDir, constFontItalic), embeddedFontItalic, 0600); err != nil {
		return "", err
	}

	if err := os.WriteFile(buildFontFilePath(fontsDir, constFontBoldItalic), embeddedFontBoldItalic, 0600); err != nil {
		return "", err
	}

	return fontsDir, nil
}
