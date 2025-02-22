// Code generated by radius-dict-gen. DO NOT EDIT.

package rfc3580

import (
	. "github.com/talkincode/greenradius/rfc2865"
	. "github.com/talkincode/greenradius/rfc2866"
	. "github.com/talkincode/greenradius/rfc2868"
)

func init() {
	AcctTerminateCause_Strings[AcctTerminateCause_Value_SupplicantRestart] = "Supplicant-Restart"
	AcctTerminateCause_Strings[AcctTerminateCause_Value_ReauthenticationFailure] = "Reauthentication-Failure"
	AcctTerminateCause_Strings[AcctTerminateCause_Value_PortReinit] = "Port-Reinit"
	AcctTerminateCause_Strings[AcctTerminateCause_Value_PortDisabled] = "Port-Disabled"
}

const (
	AcctTerminateCause_Value_SupplicantRestart       AcctTerminateCause = 19
	AcctTerminateCause_Value_ReauthenticationFailure AcctTerminateCause = 20
	AcctTerminateCause_Value_PortReinit              AcctTerminateCause = 21
	AcctTerminateCause_Value_PortDisabled            AcctTerminateCause = 22
)

func init() {
	NASPortType_Strings[NASPortType_Value_TokenRing] = "Token-Ring"
	NASPortType_Strings[NASPortType_Value_FDDI] = "FDDI"
}

const (
	NASPortType_Value_TokenRing NASPortType = 20
	NASPortType_Value_FDDI      NASPortType = 21
)

func init() {
	TunnelType_Strings[TunnelType_Value_VLAN] = "VLAN"
}

const (
	TunnelType_Value_VLAN TunnelType = 13
)
