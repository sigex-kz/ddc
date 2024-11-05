//go:build !js
// +build !js

/*
Copyright 2020 The pdfcpu Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package model

import (
	"bytes"
	"io"

	"github.com/pkg/errors"
	"github.com/vsenko/pdfcpu/pkg/pdfcpu/types"
	"gopkg.in/yaml.v2"
)

type configuration struct {
	CreationDate                    string `yaml:"created"`
	Version                         string `yaml:"version"`
	CheckFileNameExt                bool   `yaml:"checkFileNameExt"`
	Reader15                        bool   `yaml:"reader15"`
	DecodeAllStreams                bool   `yaml:"decodeAllStreams"`
	ValidationMode                  string `yaml:"validationMode"`
	PostProcessValidate             bool   `yaml:"postProcessValidate"`
	Eol                             string `yaml:"eol"`
	WriteObjectStream               bool   `yaml:"writeObjectStream"`
	WriteXRefStream                 bool   `yaml:"writeXRefStream"`
	EncryptUsingAES                 bool   `yaml:"encryptUsingAES"`
	EncryptKeyLength                int    `yaml:"encryptKeyLength"`
	Permissions                     int    `yaml:"permissions"`
	Unit                            string `yaml:"unit"`
	Units                           string `yaml:"units"` // Be flexible if version < v0.3.8
	TimestampFormat                 string `yaml:"timestampFormat"`
	DateFormat                      string `yaml:"dateFormat"`
	Optimize                        bool   `yaml:"optimize"`
	OptimizeBeforeWriting           bool
	OptimizeResourceDicts           bool `yaml:"optimizeResourceDicts"`
	OptimizeDuplicateContentStreams bool `yaml:"optimizeDuplicateContentStreams"`
	CreateBookmarks                 bool `yaml:"createBookmarks"`
	NeedAppearances                 bool `yaml:"needAppearances"`
	Offline                         bool `yaml:"offline"`
	Timeout                         int  `yaml:"timeout"`
}

func loadedConfig(c configuration, configPath string) *Configuration {
	var conf Configuration
	conf.Path = configPath

	conf.CreationDate = c.CreationDate
	conf.Version = c.Version
	conf.CheckFileNameExt = c.CheckFileNameExt
	conf.Reader15 = c.Reader15
	conf.DecodeAllStreams = c.DecodeAllStreams
	conf.WriteObjectStream = c.WriteObjectStream
	conf.WriteXRefStream = c.WriteXRefStream
	conf.EncryptUsingAES = c.EncryptUsingAES
	conf.EncryptKeyLength = c.EncryptKeyLength
	conf.Permissions = PermissionFlags(c.Permissions)

	switch c.ValidationMode {
	case "ValidationStrict":
		conf.ValidationMode = ValidationStrict
	case "ValidationRelaxed":
		conf.ValidationMode = ValidationRelaxed
	}

	conf.PostProcessValidate = c.PostProcessValidate

	switch c.Eol {
	case "EolLF":
		conf.Eol = types.EolLF
	case "EolCR":
		conf.Eol = types.EolCR
	case "EolCRLF":
		conf.Eol = types.EolCRLF
	}

	switch c.Unit {
	case "points":
		conf.Unit = types.POINTS
	case "inches":
		conf.Unit = types.INCHES
	case "cm":
		conf.Unit = types.CENTIMETRES
	case "mm":
		conf.Unit = types.MILLIMETRES
	}

	conf.TimestampFormat = c.TimestampFormat
	conf.DateFormat = c.DateFormat
	conf.Optimize = c.Optimize

	// TODO add to config.yml
	conf.OptimizeBeforeWriting = true

	conf.OptimizeResourceDicts = c.OptimizeResourceDicts
	conf.OptimizeDuplicateContentStreams = c.OptimizeDuplicateContentStreams
	conf.CreateBookmarks = c.CreateBookmarks
	conf.NeedAppearances = c.NeedAppearances
	conf.Offline = c.Offline
	conf.Timeout = c.Timeout

	return &conf
}

func parseConfigFile(r io.Reader, configPath string) error {
	var c configuration

	// Enforce default for old config files.
	c.CheckFileNameExt = true

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return err
	}

	if err := yaml.Unmarshal(buf.Bytes(), &c); err != nil {
		return err
	}

	if !types.MemberOf(c.ValidationMode, []string{"ValidationStrict", "ValidationRelaxed"}) {
		return errors.Errorf("invalid validationMode: %s", c.ValidationMode)
	}
	if !types.MemberOf(c.Eol, []string{"EolLF", "EolCR", "EolCRLF"}) {
		return errors.Errorf("invalid eol: %s", c.Eol)
	}
	if c.Unit == "" {
		// v0.3.8 modifies "units" to "unit".
		if c.Units != "" {
			c.Unit = c.Units
		}
	}
	if !types.MemberOf(c.Unit, []string{"points", "inches", "cm", "mm"}) {
		return errors.Errorf("invalid unit: %s", c.Unit)
	}

	if !types.IntMemberOf(c.EncryptKeyLength, []int{40, 128, 256}) {
		return errors.Errorf("encryptKeyLength possible values: 40, 128, 256, got: %s", c.Unit)
	}

	loadedDefaultConfig = loadedConfig(c, configPath)

	return nil
}
