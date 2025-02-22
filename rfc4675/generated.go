// Code generated by radius-dict-gen. DO NOT EDIT.

package rfc4675

import (
	"strconv"

	"github.com/talkincode/greenradius"
)

const (
	EgressVLANID_Type      radius.Type = 56
	IngressFilters_Type    radius.Type = 57
	EgressVLANName_Type    radius.Type = 58
	UserPriorityTable_Type radius.Type = 59
)

type EgressVLANID uint32

var EgressVLANID_Strings = map[EgressVLANID]string{}

func (a EgressVLANID) String() string {
	if str, ok := EgressVLANID_Strings[a]; ok {
		return str
	}
	return "EgressVLANID(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func EgressVLANID_Add(p *radius.Packet, value EgressVLANID) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(EgressVLANID_Type, a)
	return
}

func EgressVLANID_Get(p *radius.Packet) (value EgressVLANID) {
	value, _ = EgressVLANID_Lookup(p)
	return
}

func EgressVLANID_Gets(p *radius.Packet) (values []EgressVLANID, err error) {
	var i uint32
	for _, avp := range p.Attributes {
		if avp.Type != EgressVLANID_Type {
			continue
		}
		attr := avp.Attribute
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, EgressVLANID(i))
	}
	return
}

func EgressVLANID_Lookup(p *radius.Packet) (value EgressVLANID, err error) {
	a, ok := p.Lookup(EgressVLANID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = EgressVLANID(i)
	return
}

func EgressVLANID_Set(p *radius.Packet, value EgressVLANID) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(EgressVLANID_Type, a)
	return
}

func EgressVLANID_Del(p *radius.Packet) {
	p.Attributes.Del(EgressVLANID_Type)
}

type IngressFilters uint32

const (
	IngressFilters_Value_Enabled  IngressFilters = 1
	IngressFilters_Value_Disabled IngressFilters = 2
)

var IngressFilters_Strings = map[IngressFilters]string{
	IngressFilters_Value_Enabled:  "Enabled",
	IngressFilters_Value_Disabled: "Disabled",
}

func (a IngressFilters) String() string {
	if str, ok := IngressFilters_Strings[a]; ok {
		return str
	}
	return "IngressFilters(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func IngressFilters_Add(p *radius.Packet, value IngressFilters) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(IngressFilters_Type, a)
	return
}

func IngressFilters_Get(p *radius.Packet) (value IngressFilters) {
	value, _ = IngressFilters_Lookup(p)
	return
}

func IngressFilters_Gets(p *radius.Packet) (values []IngressFilters, err error) {
	var i uint32
	for _, avp := range p.Attributes {
		if avp.Type != IngressFilters_Type {
			continue
		}
		attr := avp.Attribute
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, IngressFilters(i))
	}
	return
}

func IngressFilters_Lookup(p *radius.Packet) (value IngressFilters, err error) {
	a, ok := p.Lookup(IngressFilters_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = IngressFilters(i)
	return
}

func IngressFilters_Set(p *radius.Packet, value IngressFilters) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(IngressFilters_Type, a)
	return
}

func IngressFilters_Del(p *radius.Packet) {
	p.Attributes.Del(IngressFilters_Type)
}

func EgressVLANName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(EgressVLANName_Type, a)
	return
}

func EgressVLANName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(EgressVLANName_Type, a)
	return
}

func EgressVLANName_Get(p *radius.Packet) (value []byte) {
	value, _ = EgressVLANName_Lookup(p)
	return
}

func EgressVLANName_GetString(p *radius.Packet) (value string) {
	value, _ = EgressVLANName_LookupString(p)
	return
}

func EgressVLANName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, avp := range p.Attributes {
		if avp.Type != EgressVLANName_Type {
			continue
		}
		attr := avp.Attribute
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func EgressVLANName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, avp := range p.Attributes {
		if avp.Type != EgressVLANName_Type {
			continue
		}
		attr := avp.Attribute
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func EgressVLANName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(EgressVLANName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func EgressVLANName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(EgressVLANName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func EgressVLANName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(EgressVLANName_Type, a)
	return
}

func EgressVLANName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(EgressVLANName_Type, a)
	return
}

func EgressVLANName_Del(p *radius.Packet) {
	p.Attributes.Del(EgressVLANName_Type)
}

func UserPriorityTable_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(UserPriorityTable_Type, a)
	return
}

func UserPriorityTable_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(UserPriorityTable_Type, a)
	return
}

func UserPriorityTable_Get(p *radius.Packet) (value []byte) {
	value, _ = UserPriorityTable_Lookup(p)
	return
}

func UserPriorityTable_GetString(p *radius.Packet) (value string) {
	value, _ = UserPriorityTable_LookupString(p)
	return
}

func UserPriorityTable_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, avp := range p.Attributes {
		if avp.Type != UserPriorityTable_Type {
			continue
		}
		attr := avp.Attribute
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserPriorityTable_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, avp := range p.Attributes {
		if avp.Type != UserPriorityTable_Type {
			continue
		}
		attr := avp.Attribute
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserPriorityTable_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(UserPriorityTable_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func UserPriorityTable_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(UserPriorityTable_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func UserPriorityTable_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(UserPriorityTable_Type, a)
	return
}

func UserPriorityTable_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(UserPriorityTable_Type, a)
	return
}

func UserPriorityTable_Del(p *radius.Packet) {
	p.Attributes.Del(UserPriorityTable_Type)
}
