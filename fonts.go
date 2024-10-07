package ddc

import (
	// To embed fonts
	_ "embed"
)

//go:embed fonts/LiberationSans-Regular.ttf
var embeddedFontRegular []byte

//go:embed fonts/LiberationSans-Bold.ttf
var embeddedFontBold []byte

//go:embed fonts/LiberationSans-Italic.ttf
var embeddedFontItalic []byte

//go:embed fonts/LiberationSans-BoldItalic.ttf
var embeddedFontBoldItalic []byte

//go:embed fonts/LiberationMono-Regular.ttf
var embeddedFontMonoRegular []byte
