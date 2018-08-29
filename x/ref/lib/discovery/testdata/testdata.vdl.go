// Copyright 2015 The Vanadium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file was auto-generated by the vanadium vdl tool.
// Package: testdata

package testdata

import (
	"v.io/v23/vdl"
	"v.io/x/ref/lib/discovery"
)

var _ = __VDLInit() // Must be first; see __VDLInit comments for details.

//////////////////////////////////////////////////
// Type definitions

// PackAddressTest represents a test case for PackAddress.
type PackAddressTest struct {
	// In is the addresses to pack.
	In []string
	// Packed is the expected packed output.
	Packed []byte
}

func (PackAddressTest) VDLReflect(struct {
	Name string `vdl:"v.io/x/ref/lib/discovery/testdata.PackAddressTest"`
}) {
}

func (x PackAddressTest) VDLIsZero() bool {
	if len(x.In) != 0 {
		return false
	}
	if len(x.Packed) != 0 {
		return false
	}
	return true
}

func (x PackAddressTest) VDLWrite(enc vdl.Encoder) error {
	if err := enc.StartValue(__VDLType_struct_1); err != nil {
		return err
	}
	if len(x.In) != 0 {
		if err := enc.NextField(0); err != nil {
			return err
		}
		if err := __VDLWriteAnon_list_1(enc, x.In); err != nil {
			return err
		}
	}
	if len(x.Packed) != 0 {
		if err := enc.NextFieldValueBytes(1, __VDLType_list_3, x.Packed); err != nil {
			return err
		}
	}
	if err := enc.NextField(-1); err != nil {
		return err
	}
	return enc.FinishValue()
}

func __VDLWriteAnon_list_1(enc vdl.Encoder, x []string) error {
	if err := enc.StartValue(__VDLType_list_2); err != nil {
		return err
	}
	if err := enc.SetLenHint(len(x)); err != nil {
		return err
	}
	for _, elem := range x {
		if err := enc.NextEntryValueString(vdl.StringType, elem); err != nil {
			return err
		}
	}
	if err := enc.NextEntry(true); err != nil {
		return err
	}
	return enc.FinishValue()
}

func (x *PackAddressTest) VDLRead(dec vdl.Decoder) error {
	*x = PackAddressTest{}
	if err := dec.StartValue(__VDLType_struct_1); err != nil {
		return err
	}
	decType := dec.Type()
	for {
		index, err := dec.NextField()
		switch {
		case err != nil:
			return err
		case index == -1:
			return dec.FinishValue()
		}
		if decType != __VDLType_struct_1 {
			index = __VDLType_struct_1.FieldIndexByName(decType.Field(index).Name)
			if index == -1 {
				if err := dec.SkipValue(); err != nil {
					return err
				}
				continue
			}
		}
		switch index {
		case 0:
			if err := __VDLReadAnon_list_1(dec, &x.In); err != nil {
				return err
			}
		case 1:
			if err := dec.ReadValueBytes(-1, &x.Packed); err != nil {
				return err
			}
		}
	}
}

func __VDLReadAnon_list_1(dec vdl.Decoder, x *[]string) error {
	if err := dec.StartValue(__VDLType_list_2); err != nil {
		return err
	}
	if len := dec.LenHint(); len > 0 {
		*x = make([]string, 0, len)
	} else {
		*x = nil
	}
	for {
		switch done, elem, err := dec.NextEntryValueString(); {
		case err != nil:
			return err
		case done:
			return dec.FinishValue()
		default:
			*x = append(*x, elem)
		}
	}
}

// PackEncryptionKeysTest represents a test case for PackEncryptionKeys
type PackEncryptionKeysTest struct {
	// Algo is the algorithm that's in use.
	// but that isn't defined in vdl yet.
	Algo discovery.EncryptionAlgorithm
	// Keys are the encryption keys.
	// but that isn't defined in vdl yet.
	Keys []discovery.EncryptionKey
	// Packed is the expected output bytes.
	Packed []byte
}

func (PackEncryptionKeysTest) VDLReflect(struct {
	Name string `vdl:"v.io/x/ref/lib/discovery/testdata.PackEncryptionKeysTest"`
}) {
}

func (x PackEncryptionKeysTest) VDLIsZero() bool {
	if x.Algo != 0 {
		return false
	}
	if len(x.Keys) != 0 {
		return false
	}
	if len(x.Packed) != 0 {
		return false
	}
	return true
}

func (x PackEncryptionKeysTest) VDLWrite(enc vdl.Encoder) error {
	if err := enc.StartValue(__VDLType_struct_4); err != nil {
		return err
	}
	if x.Algo != 0 {
		if err := enc.NextFieldValueInt(0, __VDLType_int32_5, int64(x.Algo)); err != nil {
			return err
		}
	}
	if len(x.Keys) != 0 {
		if err := enc.NextField(1); err != nil {
			return err
		}
		if err := __VDLWriteAnon_list_2(enc, x.Keys); err != nil {
			return err
		}
	}
	if len(x.Packed) != 0 {
		if err := enc.NextFieldValueBytes(2, __VDLType_list_3, x.Packed); err != nil {
			return err
		}
	}
	if err := enc.NextField(-1); err != nil {
		return err
	}
	return enc.FinishValue()
}

func __VDLWriteAnon_list_2(enc vdl.Encoder, x []discovery.EncryptionKey) error {
	if err := enc.StartValue(__VDLType_list_6); err != nil {
		return err
	}
	if err := enc.SetLenHint(len(x)); err != nil {
		return err
	}
	for _, elem := range x {
		if err := enc.NextEntryValueBytes(__VDLType_list_7, []byte(elem)); err != nil {
			return err
		}
	}
	if err := enc.NextEntry(true); err != nil {
		return err
	}
	return enc.FinishValue()
}

func (x *PackEncryptionKeysTest) VDLRead(dec vdl.Decoder) error {
	*x = PackEncryptionKeysTest{}
	if err := dec.StartValue(__VDLType_struct_4); err != nil {
		return err
	}
	decType := dec.Type()
	for {
		index, err := dec.NextField()
		switch {
		case err != nil:
			return err
		case index == -1:
			return dec.FinishValue()
		}
		if decType != __VDLType_struct_4 {
			index = __VDLType_struct_4.FieldIndexByName(decType.Field(index).Name)
			if index == -1 {
				if err := dec.SkipValue(); err != nil {
					return err
				}
				continue
			}
		}
		switch index {
		case 0:
			switch value, err := dec.ReadValueInt(32); {
			case err != nil:
				return err
			default:
				x.Algo = discovery.EncryptionAlgorithm(value)
			}
		case 1:
			if err := __VDLReadAnon_list_2(dec, &x.Keys); err != nil {
				return err
			}
		case 2:
			if err := dec.ReadValueBytes(-1, &x.Packed); err != nil {
				return err
			}
		}
	}
}

func __VDLReadAnon_list_2(dec vdl.Decoder, x *[]discovery.EncryptionKey) error {
	if err := dec.StartValue(__VDLType_list_6); err != nil {
		return err
	}
	if len := dec.LenHint(); len > 0 {
		*x = make([]discovery.EncryptionKey, 0, len)
	} else {
		*x = nil
	}
	for {
		switch done, err := dec.NextEntry(); {
		case err != nil:
			return err
		case done:
			return dec.FinishValue()
		default:
			var elem discovery.EncryptionKey
			var bytes []byte
			if err := dec.ReadValueBytes(-1, &bytes); err != nil {
				return err
			}
			elem = bytes
			*x = append(*x, elem)
		}
	}
}

// UuidTestData represents the inputs and outputs for a uuid test.
type UuidTestData struct {
	// In is the input string.
	In string
	// Want is the expected uuid's human-readable string form.
	Want string
}

func (UuidTestData) VDLReflect(struct {
	Name string `vdl:"v.io/x/ref/lib/discovery/testdata.UuidTestData"`
}) {
}

func (x UuidTestData) VDLIsZero() bool {
	return x == UuidTestData{}
}

func (x UuidTestData) VDLWrite(enc vdl.Encoder) error {
	if err := enc.StartValue(__VDLType_struct_8); err != nil {
		return err
	}
	if x.In != "" {
		if err := enc.NextFieldValueString(0, vdl.StringType, x.In); err != nil {
			return err
		}
	}
	if x.Want != "" {
		if err := enc.NextFieldValueString(1, vdl.StringType, x.Want); err != nil {
			return err
		}
	}
	if err := enc.NextField(-1); err != nil {
		return err
	}
	return enc.FinishValue()
}

func (x *UuidTestData) VDLRead(dec vdl.Decoder) error {
	*x = UuidTestData{}
	if err := dec.StartValue(__VDLType_struct_8); err != nil {
		return err
	}
	decType := dec.Type()
	for {
		index, err := dec.NextField()
		switch {
		case err != nil:
			return err
		case index == -1:
			return dec.FinishValue()
		}
		if decType != __VDLType_struct_8 {
			index = __VDLType_struct_8.FieldIndexByName(decType.Field(index).Name)
			if index == -1 {
				if err := dec.SkipValue(); err != nil {
					return err
				}
				continue
			}
		}
		switch index {
		case 0:
			switch value, err := dec.ReadValueString(); {
			case err != nil:
				return err
			default:
				x.In = value
			}
		case 1:
			switch value, err := dec.ReadValueString(); {
			case err != nil:
				return err
			default:
				x.Want = value
			}
		}
	}
}

//////////////////////////////////////////////////
// Const definitions

var PackAddressTestData = []PackAddressTest{
	{
		In: []string{
			"a12345",
		},
		Packed: []byte("\x06a12345\x00"),
	},
	{
		In: []string{
			"a1234",
			"b5678",
			"c9012",
		},
		Packed: []byte("\x05a1234\x05b5678\x05c9012\x00"),
	},
	{},
	{
		In: []string{
			"/@6@wsh@100.110.64.64:47011@@2c8d255c1b25e90cba07f5c857086e3b@s@idprovider:o:there_was_a_very_long_application_identifier_at_this_point_right_here:username@someplace.com@@",
			"/@6@wsh@8.34.219.227:8100@@2c8d255c1b25e90cba07f5c857086e3b@s@idprovider:o:there_was_a_very_long_application_identifier_at_this_point_right_here:username@someplace.com@@",
			"/@6@wsh@[2620:0:1000:fd86:66bc:cff:fe51:6cb4]:47011@@2c8d255c1b25e90cba07f5c857086e3b@s@idprovider:o:there_was_a_very_long_application_identifier_at_this_point_right_here:username@someplace.com@@",
			"/@6@wsh@[2620:0:1000:fd86:d94b:86d7:caff:b48f]:47011@@2c8d255c1b25e90cba07f5c857086e3b@s@idprovider:o:there_was_a_very_long_application_identifier_at_this_point_right_here:username@someplace.com@@",
			"/@6@wsh@[fe80::2409:8aff:fe2e:f60e]:47011@@2c8d255c1b25e90cba07f5c857086e3b@s@idprovider:o:there_was_a_very_long_application_identifier_at_this_point_right_here:username@someplace.com@@",
			"/@6@wsh@[fe80::66bc:cff:fe51:6cb4]:47011@@2c8d255c1b25e90cba07f5c857086e3b@s@idprovider:o:there_was_a_very_long_application_identifier_at_this_point_right_here:username@someplace.com@@",
			"/@6@wsh@[fe80::f33f:4a65:4fe7:fc38]:47011@@2c8d255c1b25e90cba07f5c857086e3b@s@idprovider:o:there_was_a_very_long_application_identifier_at_this_point_right_here:username@someplace.com@@",
		},
		Packed: []byte("\xd4\xd2_J\xc40\x10\xc7q\xbcP\x9d\xa4i\x9a\xceS\xee!\x12\xf2gf\x1b\xd8mJ\x1aw\xf1H\xe2\x05\xf4Y\x0f&\xfa\xb0\x82\x82\xcf\xf5\x00\x81\xcf\xf7\x97y\xbe\xb9\xb5\xda^\xb6\xd9\n\x80N\b\xe8\xb4\xea\xb4B5\x82\x10\xd6\xcah\x92\x1c\x86(\x82\x1ch\x82\x18<\x8c<D3\x8c`4\xf5\xc1n6\xa7\xb5\x96sNT\xb1`\x9b\xa9\x92\xbb\xf8\xcdyw\xa6\xfa\xe8\x8ee98\xbf\xae\xc7\x1c}\xcbeq9\xd1\xd22g\xaa\xce7\xd7漹\xb5䥹\x9a\x0fss\x9f\xef\xf1a\xa3\xba\xf8\x13٭\x9ch=\xfaH],'k\x9f\xaeX\xd3\xf5\xaa\x93b\xea\xa4\x1c\xd1\b\x80\xbdQ߮\xd4;\xa9% \xa0\x00\x00\xe4d4j\x1d\"Ffd\x1a\x04\xea\x18\xd4\xfd>\xf7~\xff#\"M*\xa0\xd1i\xc4\xe8\x991(\xc3;\xadx\xfd\xae`2\x80(\x15Lh\xfc\xd7\aHB\xd6@;\xa5\xbf\xfc\xa4\xff\x9b\xd3\xf95:\xf7=\xa3\xf2z@\xc54\"\xc7\xde\xec\x94\xfe\x11\x00\x00\xff\xff\x01"),
	},
}
var PackEncryptionKeysTestData = []PackEncryptionKeysTest{
	{
		Algo: 1,
		Keys: []discovery.EncryptionKey{
			discovery.EncryptionKey("0123456789"),
		},
		Packed: []byte("\x01\n0123456789"),
	},
	{
		Algo: 2,
		Keys: []discovery.EncryptionKey{
			discovery.EncryptionKey("012345"),
			discovery.EncryptionKey("123456"),
			discovery.EncryptionKey("234567"),
		},
		Packed: []byte("\x02\x06012345\x06123456\x06234567"),
	},
	{
		Packed: []byte("\x00"),
	},
}
var ServiceUuidTest = []UuidTestData{
	{
		In:   "v.io",
		Want: "2101363c-688d-548a-a600-34d506e1aad0",
	},
	{
		In:   "v.io/v23/abc",
		Want: "6726c4e5-b6eb-5547-9228-b2913f4fad52",
	},
	{
		In:   "v.io/v23/abc/xyz",
		Want: "be8a57d7-931d-5ee4-9243-0bebde0029a5",
	},
}
var AttributeUuidTest = []UuidTestData{
	{
		In:   "name",
		Want: "217a496d-3aae-5748-baf0-a77555f8f4f4",
	},
	{
		In:   "_attr",
		Want: "6c020e4b-9a59-5c7f-92e7-45954a16a402",
	},
	{
		In:   "xyz",
		Want: "c10b25a2-2d4d-5a19-bb7c-1ee1c4972b4c",
	},
}

// Hold type definitions in package-level variables, for better performance.
var (
	__VDLType_struct_1 *vdl.Type
	__VDLType_list_2   *vdl.Type
	__VDLType_list_3   *vdl.Type
	__VDLType_struct_4 *vdl.Type
	__VDLType_int32_5  *vdl.Type
	__VDLType_list_6   *vdl.Type
	__VDLType_list_7   *vdl.Type
	__VDLType_struct_8 *vdl.Type
)

var __VDLInitCalled bool

// __VDLInit performs vdl initialization.  It is safe to call multiple times.
// If you have an init ordering issue, just insert the following line verbatim
// into your source files in this package, right after the "package foo" clause:
//
//    var _ = __VDLInit()
//
// The purpose of this function is to ensure that vdl initialization occurs in
// the right order, and very early in the init sequence.  In particular, vdl
// registration and package variable initialization needs to occur before
// functions like vdl.TypeOf will work properly.
//
// This function returns a dummy value, so that it can be used to initialize the
// first var in the file, to take advantage of Go's defined init order.
func __VDLInit() struct{} {
	if __VDLInitCalled {
		return struct{}{}
	}
	__VDLInitCalled = true

	// Register types.
	vdl.Register((*PackAddressTest)(nil))
	vdl.Register((*PackEncryptionKeysTest)(nil))
	vdl.Register((*UuidTestData)(nil))

	// Initialize type definitions.
	__VDLType_struct_1 = vdl.TypeOf((*PackAddressTest)(nil)).Elem()
	__VDLType_list_2 = vdl.TypeOf((*[]string)(nil))
	__VDLType_list_3 = vdl.TypeOf((*[]byte)(nil))
	__VDLType_struct_4 = vdl.TypeOf((*PackEncryptionKeysTest)(nil)).Elem()
	__VDLType_int32_5 = vdl.TypeOf((*discovery.EncryptionAlgorithm)(nil))
	__VDLType_list_6 = vdl.TypeOf((*[]discovery.EncryptionKey)(nil))
	__VDLType_list_7 = vdl.TypeOf((*discovery.EncryptionKey)(nil))
	__VDLType_struct_8 = vdl.TypeOf((*UuidTestData)(nil)).Elem()

	return struct{}{}
}