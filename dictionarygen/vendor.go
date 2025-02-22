package dictionarygen

import (
	"io"

	"github.com/talkincode/greenradius/dictionary"
)

func (g *Generator) genVendor(w io.Writer, vendor *dictionary.Vendor) {
	ident := identifier(vendor.Name)

	p(w)
	p(w, `func _`, ident, `_AddVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {`)
	p(w, `	var vsa radius.Attribute`)
	p(w, `	vendor := make(radius.Attribute, 2+len(attr))`)
	p(w, `	vendor[0] = typ`)
	p(w, `	vendor[1] = byte(len(vendor))`)
	p(w, `	copy(vendor[2:], attr)`)
	p(w, `	vsa, err = radius.NewVendorSpecific(_`, ident, `_VendorID, vendor)`)
	p(w, `	if err != nil {`)
	p(w, `		return`)
	p(w, `	}`)
	p(w, `	p.Add(rfc2865.VendorSpecific_Type, vsa)`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_GetsVendor(p *radius.Packet, typ byte) (values []radius.Attribute) {`)
	p(w, `	for _, avp := range p.Attributes {`)
	p(w, `		if avp.Type != rfc2865.VendorSpecific_Type {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		attr := avp.Attribute`)
	p(w, `		vendorID, vsa, err := radius.VendorSpecific(attr)`)
	p(w, `		if err != nil || vendorID != _`, ident, `_VendorID {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		for len(vsa) >= 3 {`)
	p(w, `			vsaTyp, vsaLen := vsa[0], vsa[1]`)
	p(w, `			if int(vsaLen) > len(vsa) || vsaLen < 3 {`) // malformed
	p(w, `				break`)
	p(w, `			}`)
	p(w, `			if vsaTyp == typ {`)
	p(w, `				values = append(values, vsa[2:int(vsaLen)])`)
	p(w, `			}`)
	p(w, `			vsa = vsa[int(vsaLen):]`)
	p(w, `		}`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_LookupVendor(p *radius.Packet, typ byte) (attr radius.Attribute, ok bool) {`)
	p(w, `	for _, avp := range p.Attributes {`)
	p(w, `		if avp.Type != rfc2865.VendorSpecific_Type {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		attr := avp.Attribute`)
	p(w, `		vendorID, vsa, err := radius.VendorSpecific(attr)`)
	p(w, `		if err != nil || vendorID != _`, ident, `_VendorID {`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		for len(vsa) >= 3 {`)
	p(w, `			vsaTyp, vsaLen := vsa[0], vsa[1]`)
	p(w, `			if int(vsaLen) > len(vsa) || vsaLen < 3 {`) // malformed
	p(w, `				break`)
	p(w, `			}`)
	p(w, `			if vsaTyp == typ {`)
	p(w, `				return vsa[2:int(vsaLen)], true`)
	p(w, `			}`)
	p(w, `			vsa = vsa[int(vsaLen):]`)
	p(w, `		}`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_SetVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {`)
	p(w, `	for i := 0; i < len(p.Attributes); {`)
	p(w, `		avp := p.Attributes[i]`)
	p(w, `		if avp.Type != rfc2865.VendorSpecific_Type {`)
	p(w, `			i++`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		vendorID, vsa, err := radius.VendorSpecific(avp.Attribute)`)
	p(w, `		if err != nil || vendorID != _`, ident, `_VendorID {`)
	p(w, `			i++`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		for j := 0; len(vsa[j:]) >= 3; {`)
	p(w, `			vsaTyp, vsaLen := vsa[0], vsa[1]`)
	p(w, `			if int(vsaLen) > len(vsa[j:]) || vsaLen < 3 {`) // malformed
	p(w, `				i++`)
	p(w, `				break`)
	p(w, `			}`)
	p(w, `			if vsaTyp == typ {`)
	p(w, `				vsa = append(vsa[:j], vsa[j+int(vsaLen):]...)`)
	p(w, `			}`)
	p(w, `			j += int(vsaLen)`)
	p(w, `		}`)
	p(w, `		if len(vsa) > 0 {`)
	p(w, `			copy(avp.Attribute[4:], vsa)`)
	p(w, `			i++`)
	p(w, `		} else {`)
	p(w, `			p.Attributes = append(p.Attributes[:i], p.Attributes[i+i:]...)`)
	p(w, `		}`)
	p(w, `	}`)
	p(w, `	return _`, ident, `_AddVendor(p, typ, attr)`)
	p(w, `}`)

	p(w)
	p(w, `func _`, ident, `_DelVendor(p *radius.Packet, typ byte) {`)
	p(w, `vsaLoop:`)
	p(w, `	for i := 0; i < len(p.Attributes); {`)
	p(w, `		avp := p.Attributes[i]`)
	p(w, `		if avp.Type != rfc2865.VendorSpecific_Type {`)
	p(w, `			i++`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		vendorID, vsa, err := radius.VendorSpecific(avp.Attribute)`)
	p(w, `		if err != nil || vendorID != _`, ident, `_VendorID {`)
	p(w, `			i++`)
	p(w, `			continue`)
	p(w, `		}`)
	p(w, `		offset := 0`)
	p(w, `		for len(vsa[offset:]) >= 3 {`)
	p(w, `			vsaTyp, vsaLen := vsa[offset], vsa[offset+1]`)
	p(w, `			if int(vsaLen) > len(vsa) || vsaLen < 3 {`) // malformed
	p(w, `				continue vsaLoop`)
	p(w, `			}`)
	p(w, `			if vsaTyp == typ {`)
	p(w, `				copy(vsa[offset:], vsa[offset+int(vsaLen):])`)
	p(w, `				vsa = vsa[:len(vsa)-int(vsaLen)]`)
	p(w, `			} else {`)
	p(w, `				offset += int(vsaLen)`)
	p(w, `			}`)
	p(w, `		}`)
	p(w, `		if offset == 0 {`)
	p(w, `			p.Attributes = append(p.Attributes[:i], p.Attributes[i+1:]...)`)
	p(w, `		} else {`)
	p(w, `			i++`)
	p(w, `		}`)
	p(w, `	}`)
	p(w, `	return`)
	p(w, `}`)
}
