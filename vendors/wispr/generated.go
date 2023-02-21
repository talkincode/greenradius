// Code generated by radius-dict-gen. DO NOT EDIT.

package wispr

import (
	"strconv"

	"github.com/talkincode/greenradius"
	"github.com/talkincode/greenradius/rfc2865"
)

const (
	_WISPr_VendorID = 14122
)

func _WISPr_AddVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {
	var vsa radius.Attribute
	vendor := make(radius.Attribute, 2+len(attr))
	vendor[0] = typ
	vendor[1] = byte(len(vendor))
	copy(vendor[2:], attr)
	vsa, err = radius.NewVendorSpecific(_WISPr_VendorID, vendor)
	if err != nil {
		return
	}
	p.Add(rfc2865.VendorSpecific_Type, vsa)
	return
}

func _WISPr_GetsVendor(p *radius.Packet, typ byte) (values []radius.Attribute) {
	for _, avp := range p.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		attr := avp.Attribute
		vendorID, vsa, err := radius.VendorSpecific(attr)
		if err != nil || vendorID != _WISPr_VendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaTyp == typ {
				values = append(values, vsa[2:int(vsaLen)])
			}
			vsa = vsa[int(vsaLen):]
		}
	}
	return
}

func _WISPr_LookupVendor(p *radius.Packet, typ byte) (attr radius.Attribute, ok bool) {
	for _, avp := range p.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		attr := avp.Attribute
		vendorID, vsa, err := radius.VendorSpecific(attr)
		if err != nil || vendorID != _WISPr_VendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaTyp == typ {
				return vsa[2:int(vsaLen)], true
			}
			vsa = vsa[int(vsaLen):]
		}
	}
	return
}

func _WISPr_SetVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {
	for i := 0; i < len(p.Attributes); {
		avp := p.Attributes[i]
		if avp.Type != rfc2865.VendorSpecific_Type {
			i++
			continue
		}
		vendorID, vsa, err := radius.VendorSpecific(avp.Attribute)
		if err != nil || vendorID != _WISPr_VendorID {
			i++
			continue
		}
		for j := 0; len(vsa[j:]) >= 3; {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa[j:]) || vsaLen < 3 {
				i++
				break
			}
			if vsaTyp == typ {
				vsa = append(vsa[:j], vsa[j+int(vsaLen):]...)
			}
			j += int(vsaLen)
		}
		if len(vsa) > 0 {
			copy(avp.Attribute[4:], vsa)
			i++
		} else {
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+i:]...)
		}
	}
	return _WISPr_AddVendor(p, typ, attr)
}

func _WISPr_DelVendor(p *radius.Packet, typ byte) {
vsaLoop:
	for i := 0; i < len(p.Attributes); {
		avp := p.Attributes[i]
		if avp.Type != rfc2865.VendorSpecific_Type {
			i++
			continue
		}
		vendorID, vsa, err := radius.VendorSpecific(avp.Attribute)
		if err != nil || vendorID != _WISPr_VendorID {
			i++
			continue
		}
		offset := 0
		for len(vsa[offset:]) >= 3 {
			vsaTyp, vsaLen := vsa[offset], vsa[offset+1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				continue vsaLoop
			}
			if vsaTyp == typ {
				copy(vsa[offset:], vsa[offset+int(vsaLen):])
				vsa = vsa[:len(vsa)-int(vsaLen)]
			} else {
				offset += int(vsaLen)
			}
		}
		if offset == 0 {
			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)
		} else {
			i++
		}
	}
	return
}

func WISPrLocationID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 1, a)
}

func WISPrLocationID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 1, a)
}

func WISPrLocationID_Get(p *radius.Packet) (value []byte) {
	value, _ = WISPrLocationID_Lookup(p)
	return
}

func WISPrLocationID_GetString(p *radius.Packet) (value string) {
	value, _ = WISPrLocationID_LookupString(p)
	return
}

func WISPrLocationID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _WISPr_GetsVendor(p, 1) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrLocationID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _WISPr_GetsVendor(p, 1) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrLocationID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _WISPr_LookupVendor(p, 1)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WISPrLocationID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _WISPr_LookupVendor(p, 1)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WISPrLocationID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 1, a)
}

func WISPrLocationID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 1, a)
}

func WISPrLocationID_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 1)
}

func WISPrLocationName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 2, a)
}

func WISPrLocationName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 2, a)
}

func WISPrLocationName_Get(p *radius.Packet) (value []byte) {
	value, _ = WISPrLocationName_Lookup(p)
	return
}

func WISPrLocationName_GetString(p *radius.Packet) (value string) {
	value, _ = WISPrLocationName_LookupString(p)
	return
}

func WISPrLocationName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _WISPr_GetsVendor(p, 2) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrLocationName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _WISPr_GetsVendor(p, 2) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrLocationName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _WISPr_LookupVendor(p, 2)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WISPrLocationName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _WISPr_LookupVendor(p, 2)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WISPrLocationName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 2, a)
}

func WISPrLocationName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 2, a)
}

func WISPrLocationName_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 2)
}

func WISPrLogoffURL_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 3, a)
}

func WISPrLogoffURL_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 3, a)
}

func WISPrLogoffURL_Get(p *radius.Packet) (value []byte) {
	value, _ = WISPrLogoffURL_Lookup(p)
	return
}

func WISPrLogoffURL_GetString(p *radius.Packet) (value string) {
	value, _ = WISPrLogoffURL_LookupString(p)
	return
}

func WISPrLogoffURL_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _WISPr_GetsVendor(p, 3) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrLogoffURL_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _WISPr_GetsVendor(p, 3) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrLogoffURL_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _WISPr_LookupVendor(p, 3)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WISPrLogoffURL_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _WISPr_LookupVendor(p, 3)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WISPrLogoffURL_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 3, a)
}

func WISPrLogoffURL_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 3, a)
}

func WISPrLogoffURL_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 3)
}

func WISPrRedirectionURL_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 4, a)
}

func WISPrRedirectionURL_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 4, a)
}

func WISPrRedirectionURL_Get(p *radius.Packet) (value []byte) {
	value, _ = WISPrRedirectionURL_Lookup(p)
	return
}

func WISPrRedirectionURL_GetString(p *radius.Packet) (value string) {
	value, _ = WISPrRedirectionURL_LookupString(p)
	return
}

func WISPrRedirectionURL_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _WISPr_GetsVendor(p, 4) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrRedirectionURL_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _WISPr_GetsVendor(p, 4) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrRedirectionURL_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _WISPr_LookupVendor(p, 4)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WISPrRedirectionURL_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _WISPr_LookupVendor(p, 4)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WISPrRedirectionURL_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 4, a)
}

func WISPrRedirectionURL_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 4, a)
}

func WISPrRedirectionURL_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 4)
}

type WISPrBandwidthMinUp uint32

var WISPrBandwidthMinUp_Strings = map[WISPrBandwidthMinUp]string{}

func (a WISPrBandwidthMinUp) String() string {
	if str, ok := WISPrBandwidthMinUp_Strings[a]; ok {
		return str
	}
	return "WISPrBandwidthMinUp(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func WISPrBandwidthMinUp_Add(p *radius.Packet, value WISPrBandwidthMinUp) (err error) {
	a := radius.NewInteger(uint32(value))
	return _WISPr_AddVendor(p, 5, a)
}

func WISPrBandwidthMinUp_Get(p *radius.Packet) (value WISPrBandwidthMinUp) {
	value, _ = WISPrBandwidthMinUp_Lookup(p)
	return
}

func WISPrBandwidthMinUp_Gets(p *radius.Packet) (values []WISPrBandwidthMinUp, err error) {
	var i uint32
	for _, attr := range _WISPr_GetsVendor(p, 5) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, WISPrBandwidthMinUp(i))
	}
	return
}

func WISPrBandwidthMinUp_Lookup(p *radius.Packet) (value WISPrBandwidthMinUp, err error) {
	a, ok := _WISPr_LookupVendor(p, 5)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = WISPrBandwidthMinUp(i)
	return
}

func WISPrBandwidthMinUp_Set(p *radius.Packet, value WISPrBandwidthMinUp) (err error) {
	a := radius.NewInteger(uint32(value))
	return _WISPr_SetVendor(p, 5, a)
}

func WISPrBandwidthMinUp_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 5)
}

type WISPrBandwidthMinDown uint32

var WISPrBandwidthMinDown_Strings = map[WISPrBandwidthMinDown]string{}

func (a WISPrBandwidthMinDown) String() string {
	if str, ok := WISPrBandwidthMinDown_Strings[a]; ok {
		return str
	}
	return "WISPrBandwidthMinDown(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func WISPrBandwidthMinDown_Add(p *radius.Packet, value WISPrBandwidthMinDown) (err error) {
	a := radius.NewInteger(uint32(value))
	return _WISPr_AddVendor(p, 6, a)
}

func WISPrBandwidthMinDown_Get(p *radius.Packet) (value WISPrBandwidthMinDown) {
	value, _ = WISPrBandwidthMinDown_Lookup(p)
	return
}

func WISPrBandwidthMinDown_Gets(p *radius.Packet) (values []WISPrBandwidthMinDown, err error) {
	var i uint32
	for _, attr := range _WISPr_GetsVendor(p, 6) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, WISPrBandwidthMinDown(i))
	}
	return
}

func WISPrBandwidthMinDown_Lookup(p *radius.Packet) (value WISPrBandwidthMinDown, err error) {
	a, ok := _WISPr_LookupVendor(p, 6)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = WISPrBandwidthMinDown(i)
	return
}

func WISPrBandwidthMinDown_Set(p *radius.Packet, value WISPrBandwidthMinDown) (err error) {
	a := radius.NewInteger(uint32(value))
	return _WISPr_SetVendor(p, 6, a)
}

func WISPrBandwidthMinDown_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 6)
}

type WISPrBandwidthMaxUp uint32

var WISPrBandwidthMaxUp_Strings = map[WISPrBandwidthMaxUp]string{}

func (a WISPrBandwidthMaxUp) String() string {
	if str, ok := WISPrBandwidthMaxUp_Strings[a]; ok {
		return str
	}
	return "WISPrBandwidthMaxUp(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func WISPrBandwidthMaxUp_Add(p *radius.Packet, value WISPrBandwidthMaxUp) (err error) {
	a := radius.NewInteger(uint32(value))
	return _WISPr_AddVendor(p, 7, a)
}

func WISPrBandwidthMaxUp_Get(p *radius.Packet) (value WISPrBandwidthMaxUp) {
	value, _ = WISPrBandwidthMaxUp_Lookup(p)
	return
}

func WISPrBandwidthMaxUp_Gets(p *radius.Packet) (values []WISPrBandwidthMaxUp, err error) {
	var i uint32
	for _, attr := range _WISPr_GetsVendor(p, 7) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, WISPrBandwidthMaxUp(i))
	}
	return
}

func WISPrBandwidthMaxUp_Lookup(p *radius.Packet) (value WISPrBandwidthMaxUp, err error) {
	a, ok := _WISPr_LookupVendor(p, 7)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = WISPrBandwidthMaxUp(i)
	return
}

func WISPrBandwidthMaxUp_Set(p *radius.Packet, value WISPrBandwidthMaxUp) (err error) {
	a := radius.NewInteger(uint32(value))
	return _WISPr_SetVendor(p, 7, a)
}

func WISPrBandwidthMaxUp_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 7)
}

type WISPrBandwidthMaxDown uint32

var WISPrBandwidthMaxDown_Strings = map[WISPrBandwidthMaxDown]string{}

func (a WISPrBandwidthMaxDown) String() string {
	if str, ok := WISPrBandwidthMaxDown_Strings[a]; ok {
		return str
	}
	return "WISPrBandwidthMaxDown(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func WISPrBandwidthMaxDown_Add(p *radius.Packet, value WISPrBandwidthMaxDown) (err error) {
	a := radius.NewInteger(uint32(value))
	return _WISPr_AddVendor(p, 8, a)
}

func WISPrBandwidthMaxDown_Get(p *radius.Packet) (value WISPrBandwidthMaxDown) {
	value, _ = WISPrBandwidthMaxDown_Lookup(p)
	return
}

func WISPrBandwidthMaxDown_Gets(p *radius.Packet) (values []WISPrBandwidthMaxDown, err error) {
	var i uint32
	for _, attr := range _WISPr_GetsVendor(p, 8) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, WISPrBandwidthMaxDown(i))
	}
	return
}

func WISPrBandwidthMaxDown_Lookup(p *radius.Packet) (value WISPrBandwidthMaxDown, err error) {
	a, ok := _WISPr_LookupVendor(p, 8)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = WISPrBandwidthMaxDown(i)
	return
}

func WISPrBandwidthMaxDown_Set(p *radius.Packet, value WISPrBandwidthMaxDown) (err error) {
	a := radius.NewInteger(uint32(value))
	return _WISPr_SetVendor(p, 8, a)
}

func WISPrBandwidthMaxDown_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 8)
}

func WISPrSessionTerminateTime_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 9, a)
}

func WISPrSessionTerminateTime_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 9, a)
}

func WISPrSessionTerminateTime_Get(p *radius.Packet) (value []byte) {
	value, _ = WISPrSessionTerminateTime_Lookup(p)
	return
}

func WISPrSessionTerminateTime_GetString(p *radius.Packet) (value string) {
	value, _ = WISPrSessionTerminateTime_LookupString(p)
	return
}

func WISPrSessionTerminateTime_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _WISPr_GetsVendor(p, 9) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrSessionTerminateTime_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _WISPr_GetsVendor(p, 9) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrSessionTerminateTime_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _WISPr_LookupVendor(p, 9)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WISPrSessionTerminateTime_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _WISPr_LookupVendor(p, 9)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WISPrSessionTerminateTime_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 9, a)
}

func WISPrSessionTerminateTime_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 9, a)
}

func WISPrSessionTerminateTime_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 9)
}

func WISPrSessionTerminateEndOfDay_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 10, a)
}

func WISPrSessionTerminateEndOfDay_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 10, a)
}

func WISPrSessionTerminateEndOfDay_Get(p *radius.Packet) (value []byte) {
	value, _ = WISPrSessionTerminateEndOfDay_Lookup(p)
	return
}

func WISPrSessionTerminateEndOfDay_GetString(p *radius.Packet) (value string) {
	value, _ = WISPrSessionTerminateEndOfDay_LookupString(p)
	return
}

func WISPrSessionTerminateEndOfDay_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _WISPr_GetsVendor(p, 10) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrSessionTerminateEndOfDay_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _WISPr_GetsVendor(p, 10) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrSessionTerminateEndOfDay_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _WISPr_LookupVendor(p, 10)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WISPrSessionTerminateEndOfDay_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _WISPr_LookupVendor(p, 10)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WISPrSessionTerminateEndOfDay_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 10, a)
}

func WISPrSessionTerminateEndOfDay_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 10, a)
}

func WISPrSessionTerminateEndOfDay_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 10)
}

func WISPrBillingClassOfService_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 11, a)
}

func WISPrBillingClassOfService_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_AddVendor(p, 11, a)
}

func WISPrBillingClassOfService_Get(p *radius.Packet) (value []byte) {
	value, _ = WISPrBillingClassOfService_Lookup(p)
	return
}

func WISPrBillingClassOfService_GetString(p *radius.Packet) (value string) {
	value, _ = WISPrBillingClassOfService_LookupString(p)
	return
}

func WISPrBillingClassOfService_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _WISPr_GetsVendor(p, 11) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrBillingClassOfService_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _WISPr_GetsVendor(p, 11) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func WISPrBillingClassOfService_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _WISPr_LookupVendor(p, 11)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func WISPrBillingClassOfService_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _WISPr_LookupVendor(p, 11)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func WISPrBillingClassOfService_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 11, a)
}

func WISPrBillingClassOfService_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _WISPr_SetVendor(p, 11, a)
}

func WISPrBillingClassOfService_Del(p *radius.Packet) {
	_WISPr_DelVendor(p, 11)
}
