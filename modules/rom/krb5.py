# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay (at) synacktiv.com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.   Fist0urs
# ----------------------------------------------------------------------------

#!/usr/bin/python

# -*- coding: utf-8 -*-

# by Fist0urs

from socket import socket

from pyasn1.type import tag, namedtype, univ, constraint, char, useful
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
import pyasn1.error
import constants

from crypto import encrypt, decrypt, checksum, RC4_HMAC, RSA_MD5
from util import epoch2gt
from struct import pack, unpack
from rom import nt_errors


NT_UNKNOWN = 0
NT_PRINCIPAL = 1
NT_SRV_INST = 2
NT_SRV_HST = 3
NT_SRV_XHST = 4
NT_UID = 5
NT_X500_PRINCIPAL = 6
NT_SMTP_NAME = 7
NT_ENTERPRISE = 10


AD_IF_RELEVANT = 1
AD_WIN2K_PAC = 128


# Copyright (c) 2013, Marc Horowitz
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Altered source by Alberto Solino (@agsolino)
# Source shamelessly included by Jean-Christophe Delaunay (@Fist0urs)
#
# Changed some of the classes names to match the RFC 4120
# Added [MS-KILE] data
# Adapted to Enum
#

class MyTicket(object):
    def __init__(self):
        # This is the kerberos version, not the service principal key
        # version number.
        self.tkt_vno = None
        self.service_principal = None
        self.encrypted_part = None

    def from_asn1(self, data):
        data = _asn1_decode(data, asn1.Ticket())
        self.tkt_vno = int(data.getComponentByName('tkt-vno'))
        self.service_principal = Principal()
        self.service_principal.from_asn1(data, 'realm', 'sname')
        self.encrypted_part = EncryptedData()
        self.encrypted_part.from_asn1(data.getComponentByName('enc-part'))
        return self

    def to_asn1(self, component):
        component.setComponentByName('tkt-vno', 5)
        component.setComponentByName('realm', self.service_principal.realm)
        asn1.seq_set(component, 'sname',
                     self.service_principal.components_to_asn1)
        asn1.seq_set(component, 'enc-part', self.encrypted_part.to_asn1)
        return component

    def __str__(self):
        return "<Ticket for %s vno %s>" % (str(self.service_principal), str(self.encrypted_part.kvno))

def _application_tag(tag_value):
    return univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed,
                int(tag_value)))

def _c(n, t):
    return t.clone(tagSet=t.tagSet + tag.Tag(tag.tagClassContext, tag.tagFormatSimple, n))

def _v(n, t):
    return t.clone(tagSet=t.tagSet + tag.Tag(tag.tagClassContext, tag.tagFormatSimple, n), cloneValueFlag=True)

def _vno_component(tag_value, name="pvno"):
    return _sequence_component(
        name, tag_value, univ.Integer(),
        subtypeSpec=constraint.ValueRangeConstraint(5, 5))

def _msg_type_component(tag_value, values):
    c = constraint.ConstraintsUnion(
        *(constraint.SingleValueConstraint(int(v)) for v in values))
    return _sequence_component('msg-type', tag_value, univ.Integer(),
                               subtypeSpec=c)

def _sequence_component(name, tag_value, type, **subkwargs):
    return namedtype.NamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

def _sequence_optional_component(name, tag_value, type, **subkwargs):
    return namedtype.OptionalNamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

def seq_set(seq, name, builder=None, *args, **kwargs):
    component = seq.setComponentByName(name).getComponentByName(name)
    if builder is not None:
        seq.setComponentByName(name, builder(component, *args, **kwargs))
    else:
        seq.setComponentByName(name)
    return seq.getComponentByName(name)

def seq_set_dict(seq, name, pairs, *args, **kwargs):
    component = seq.setComponentByName(name).getComponentByName(name)
    for k, v in pairs.iteritems():
        component.setComponentByName(k, v)

def seq_set_iter(seq, name, iterable):
    component = seq.setComponentByName(name).getComponentByName(name)
    for pos, v in enumerate(iterable):
        component.setComponentByPosition(pos, v)

def seq_set_flags(seq, name, flags):
    seq_set(seq, name, flags.to_asn1)

def seq_append(seq, name, pairs):
    component = seq.getComponentByName(name)
    if component is None:
        component = seq.setComponentByName(name).getComponentByName(name)
    index = len(component)
    element = component.setComponentByPosition(index
                                               ).getComponentByPosition(index)
    for k, v in pairs.iteritems():
        element.setComponentByName(k, v)

class Int32(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        -2147483648, 2147483647)

class UInt32(univ.Integer):
    pass
#    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
#        0, 4294967295)

class Microseconds(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 999999)

class KerberosString(char.GeneralString):
    # TODO marc: I'm not sure how to express this constraint in the API.
    # For now, we will be liberal in what we accept.
    # subtypeSpec = constraint.PermittedAlphabetConstraint(char.IA5String())
    pass

class Realm(KerberosString):
    pass

class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("name-type", 0, Int32()),
        _sequence_component("name-string", 1,
                            univ.SequenceOf(componentType=KerberosString()))
                            )

class KerberosTime(useful.GeneralizedTime):
    pass

class HostAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("addr-type", 0, Int32()),
        _sequence_component("address", 1, univ.OctetString())
        )

class HostAddresses(univ.SequenceOf):
    componentType = HostAddress()

class AuthorizationData(univ.SequenceOf):
    componentType = univ.Sequence(componentType=namedtype.NamedTypes(
        _sequence_component('ad-type', 0, Int32()),
        _sequence_component('ad-data', 1, univ.OctetString())
        ))

class PA_DATA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('padata-type', 1, Int32()),
        _sequence_component('padata-value', 2, univ.OctetString())
        )

class KerberosFlags(univ.BitString):
    # TODO marc: it doesn't look like there's any way to specify the
    # SIZE (32.. MAX) parameter to the encoder.  However, we can
    # arrange at a higher layer to pass in >= 32 bits to the encoder.
    pass

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("etype", 0, Int32()),
        _sequence_optional_component("kvno", 1, UInt32()),
        _sequence_component("cipher", 2, univ.OctetString())
        )

class EncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('keytype', 0, Int32()),
        _sequence_component('keyvalue', 1, univ.OctetString()))

class Checksum(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('cksumtype', 0, Int32()),
        _sequence_component('checksum', 1, univ.OctetString()))

class Ticket(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.Ticket.value)
    componentType = namedtype.NamedTypes(
        _vno_component(name="tkt-vno", tag_value=0),
        _sequence_component("realm", 1, Realm()),
        _sequence_component("sname", 2, PrincipalName()),
        _sequence_component("enc-part", 3, EncryptedData())
        )

class TicketFlags(KerberosFlags):
    pass

class TransitedEncoding(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('tr-type', 0, Int32()),
        _sequence_component('contents', 1, univ.OctetString()))

class EncTicketPart(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncTicketPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component("flags", 0, TicketFlags()),
        _sequence_component("key", 1, EncryptionKey()),
        _sequence_component("crealm", 2, Realm()),
        _sequence_component("cname", 3, PrincipalName()),
        _sequence_component("transited", 4, TransitedEncoding()),
        _sequence_component("authtime", 5, KerberosTime()),
        _sequence_optional_component("starttime", 6, KerberosTime()),
        _sequence_component("endtime", 7, KerberosTime()),
        _sequence_optional_component("renew-till", 8, KerberosTime()),
        _sequence_optional_component("caddr", 9, HostAddresses()),
        _sequence_optional_component("authorization-data", 10, AuthorizationData())
        )

class KDCOptions(KerberosFlags):
    pass

class KDC_REQ_BODY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('kdc-options', 0, KDCOptions()),
        _sequence_optional_component('cname', 1, PrincipalName()),
        _sequence_component('realm', 2, Realm()),
        _sequence_optional_component('sname', 3, PrincipalName()),
        _sequence_optional_component('from', 4, KerberosTime()),
        _sequence_component('till', 5, KerberosTime()),
        _sequence_optional_component('rtime', 6, KerberosTime()),
        _sequence_component('nonce', 7, UInt32()),
        _sequence_component('etype', 8,
                            univ.SequenceOf(componentType=Int32())),
        _sequence_optional_component('addresses', 9, HostAddresses()),
        _sequence_optional_component('enc-authorization-data', 10,
                                     EncryptedData()),
        _sequence_optional_component('additional-tickets', 11,
                                     univ.SequenceOf(componentType=Ticket()))
        )

class KDC_REQ(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _vno_component(1),
        _msg_type_component(2, (constants.ApplicationTagNumbers.AS_REQ.value,
                                constants.ApplicationTagNumbers.TGS_REQ.value)),
        _sequence_optional_component('padata', 3,
                                     univ.SequenceOf(componentType=PA_DATA())),
        _sequence_component('req-body', 4, KDC_REQ_BODY())
        )

class AS_REQ(KDC_REQ):
    tagSet = _application_tag(constants.ApplicationTagNumbers.AS_REQ.value)

class TGS_REQ(KDC_REQ):
    tagSet = _application_tag(constants.ApplicationTagNumbers.TGS_REQ.value)

class KDC_REP(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.AS_REP.value,
                                constants.ApplicationTagNumbers.TGS_REP.value)),
        _sequence_optional_component('padata', 2,
                                     univ.SequenceOf(componentType=PA_DATA())),
        _sequence_component('crealm', 3, Realm()),
        _sequence_component('cname', 4, PrincipalName()),
        _sequence_component('ticket', 5, Ticket()),
        _sequence_component('enc-part', 6, EncryptedData())
        )

class LastReq(univ.SequenceOf):
    componentType = univ.Sequence(componentType=namedtype.NamedTypes(
        _sequence_component('lr-type', 0, Int32()),
        _sequence_component('lr-value', 1, KerberosTime())
        ))

class METHOD_DATA(univ.SequenceOf):
    componentType = PA_DATA()

class EncKDCRepPart(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('key', 0, EncryptionKey()),
        _sequence_component('last-req', 1, LastReq()),
        _sequence_component('nonce', 2, UInt32()),
        _sequence_optional_component('key-expiration', 3, KerberosTime()),
        _sequence_component('flags', 4, TicketFlags()),
        _sequence_component('authtime', 5, KerberosTime()),
        _sequence_optional_component('starttime', 6, KerberosTime()),
        _sequence_component('endtime', 7, KerberosTime()),
        _sequence_optional_component('renew-till', 8, KerberosTime()),
        _sequence_component('srealm', 9, Realm()),
        _sequence_component('sname', 10, PrincipalName()),
        _sequence_optional_component('caddr', 11, HostAddresses()),
        _sequence_optional_component('encrypted_pa_data', 12, METHOD_DATA())
        )

class EncASRepPart(EncKDCRepPart):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncASRepPart.value)

class EncTGSRepPart(EncKDCRepPart):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncTGSRepPart.value)

class AS_REP(KDC_REP):
    tagSet = _application_tag(constants.ApplicationTagNumbers.AS_REP.value)

class TGS_REP(KDC_REP):
    tagSet = _application_tag(constants.ApplicationTagNumbers.TGS_REP.value)

class APOptions(KerberosFlags):
    pass

class Authenticator(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.Authenticator.value)
    componentType = namedtype.NamedTypes(
        _vno_component(name='authenticator-vno', tag_value=0),
        _sequence_component('crealm', 1, Realm()),
        _sequence_component('cname', 2, PrincipalName()),
        _sequence_optional_component('cksum', 3, Checksum()),
        _sequence_component('cusec', 4, Microseconds()),
        _sequence_component('ctime', 5, KerberosTime()),
        _sequence_optional_component('subkey', 6, EncryptionKey()),
        _sequence_optional_component('seq-number', 7, UInt32()),
        _sequence_optional_component('authorization-data', 8,
                                     AuthorizationData())
        )

class AP_REQ(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.AP_REQ.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.AP_REQ.value,)),
        _sequence_component('ap-options', 2, APOptions()),
        _sequence_component('ticket', 3, Ticket()),
        _sequence_component('authenticator', 4, EncryptedData())
        )

class AP_REP(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.AP_REP.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.AP_REP.value,)),
        _sequence_component('enc-part', 2, EncryptedData()),
        )

class EncAPRepPart(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncApRepPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component('ctime', 0, KerberosTime()),
        _sequence_component('cusec', 1, Microseconds()),
        _sequence_optional_component('subkey', 2, EncryptionKey()),
        _sequence_optional_component('seq-number', 3, UInt32()),
        )

class KRB_SAFE_BODY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('user-data', 0, univ.OctetString()),
        _sequence_optional_component('timestamp', 1, KerberosTime()),
        _sequence_optional_component('usec', 2, Microseconds()),
        _sequence_optional_component('seq-number', 3, UInt32()),
        _sequence_component('s-address', 4, HostAddress()),
        _sequence_optional_component('r-address', 5, HostAddress()),
        )

class KRB_SAFE(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_SAFE.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_SAFE.value,)),
        _sequence_component('safe-body', 2, KRB_SAFE_BODY()),
        _sequence_component('cksum', 3, Checksum()),
        )

class KRB_PRIV(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_PRIV.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_PRIV.value,)),
        _sequence_component('enc-part', 3, EncryptedData()),
        )

class EncKrbPrivPart(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncKrbPrivPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component('user-data', 0, univ.OctetString()),
        _sequence_optional_component('timestamp', 1, KerberosTime()),
        _sequence_optional_component('cusec', 2, Microseconds()),
        _sequence_optional_component('seq-number', 3, UInt32()),
        _sequence_component('s-address', 4, HostAddress()),
        _sequence_optional_component('r-address', 5, HostAddress()),
        )

class KRB_CRED(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_CRED.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_CRED.value,)),
        _sequence_optional_component('tickets', 2,
                                     univ.SequenceOf(componentType=Ticket())),
        _sequence_component('enc-part', 3, EncryptedData()),
        )

class KrbCredInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('key', 0, EncryptionKey()),
        _sequence_optional_component('prealm', 1, Realm()),
        _sequence_optional_component('pname', 2, PrincipalName()),
        _sequence_optional_component('flags', 3, TicketFlags()),
        _sequence_optional_component('authtime', 4, KerberosTime()),
        _sequence_optional_component('starttime', 5, KerberosTime()),
        _sequence_optional_component('endtime', 6, KerberosTime()),
        _sequence_optional_component('renew-till', 7, KerberosTime()),
        _sequence_optional_component('srealm', 8, Realm()),
        _sequence_optional_component('sname', 9, PrincipalName()),
        _sequence_optional_component('caddr', 10, HostAddresses()),
        )

class EncKrbCredPart(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncKrbCredPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component('ticket-info', 0, univ.SequenceOf(componentType=KrbCredInfo())),
        _sequence_optional_component('nonce', 1, UInt32()),
        _sequence_optional_component('timestamp', 2, KerberosTime()),
        _sequence_optional_component('usec', 3, Microseconds()),
        _sequence_optional_component('s-address', 4, HostAddress()),
        _sequence_optional_component('r-address', 5, HostAddress()),
        )

class KRB_ERROR(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_ERROR.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_ERROR.value,)),
        _sequence_optional_component('ctime', 2, KerberosTime()),
        _sequence_optional_component('cusec', 3, Microseconds()),
        _sequence_component('stime', 4, KerberosTime()),
        _sequence_component('susec', 5, Microseconds()),
        _sequence_component('error-code', 6, Int32()),
        _sequence_optional_component('crealm', 7, Realm()),
        _sequence_optional_component('cname', 8, PrincipalName()),
        _sequence_component('realm', 9, Realm()),
        _sequence_component('sname', 10, PrincipalName()),
        _sequence_optional_component('e-text', 11, KerberosString()),
        _sequence_optional_component('e-data', 12, univ.OctetString())
        )

class TYPED_DATA(univ.SequenceOf):
    componentType = namedtype.NamedTypes(
        _sequence_component('data-type', 0, Int32()),
        _sequence_optional_component('data-value', 1, univ.OctetString()),
    )

class PA_ENC_TIMESTAMP(EncryptedData):
    pass

class PA_ENC_TS_ENC(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('patimestamp', 0, KerberosTime()),
        _sequence_optional_component('pausec', 1, Microseconds()))

class ETYPE_INFO_ENTRY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('etype', 0, Int32()),
        _sequence_optional_component('salt', 1, univ.OctetString()))

class ETYPE_INFO(univ.SequenceOf):
    componentType = ETYPE_INFO_ENTRY()

class ETYPE_INFO2_ENTRY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('etype', 0, Int32()),
        _sequence_optional_component('salt', 1, KerberosString()),
        _sequence_optional_component('s2kparams', 2, univ.OctetString()))

class ETYPE_INFO2(univ.SequenceOf):
    componentType = ETYPE_INFO2_ENTRY()

class AD_IF_RELEVANT(AuthorizationData):
    pass

class AD_KDCIssued(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('ad-checksum', 0, Checksum()),
        _sequence_optional_component('i-realm', 1, Realm()),
        _sequence_optional_component('i-sname', 2, PrincipalName()),
        _sequence_component('elements', 3, AuthorizationData()))

class AD_AND_OR(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('condition-count', 0, Int32()),
        _sequence_optional_component('elements', 1, AuthorizationData()))

class AD_MANDATORY_FOR_KDC(AuthorizationData):
    pass

class KERB_PA_PAC_REQUEST(univ.Sequence):
    componentType = namedtype.NamedTypes(
    namedtype.NamedType('include-pac', univ.Boolean().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    )

class PA_FOR_USER_ENC(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('userName', 0, PrincipalName()),
        _sequence_optional_component('userRealm', 1, Realm()),
        _sequence_optional_component('cksum', 2, Checksum()),
        _sequence_optional_component('auth-package', 3, KerberosString()))

class KERB_ERROR_DATA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('data-type', 1, Int32()),
        _sequence_component('data-value', 2, univ.OctetString()))

class PA_PAC_OPTIONS(univ.SequenceOf):
    componentType = KerberosFlags()


def build_req_body(realm, service, host, nonce, cname=None, authorization_data=None, etype=RC4_HMAC):
    req_body = KDC_REQ_BODY()

    # (Forwardable, Proxiable, Renewable, Canonicalize)
    req_body['kdc-options'] = "'01010000100000000000000000000000'B"

    if cname is not None:
        req_body['cname'] = None
        req_body['cname']
        req_body['cname']['name-type'] = NT_SRV_INST
        req_body['cname']['name-string'] = None
        req_body['cname']['name-string'][0] = cname

    req_body['realm'] = realm

    req_body['sname'] = None
    req_body['sname']['name-type'] = NT_SRV_INST
    req_body['sname']['name-string'] = None
    req_body['sname']['name-string'][0] = service
    req_body['sname']['name-string'][1] = realm
    if (host != ''):
        req_body['sname']['name-string'][1] = host
    #else:
    #    req_body['sname']['name-string'][1] = host
    #    req_body['sname']['name-string'][2] = realm

    req_body['from'] = '19700101000000Z'
    req_body['till'] = '19700101000000Z'
    req_body['rtime'] = '19700101000000Z'
    req_body['nonce'] = nonce

    req_body['etype'] = None
    req_body['etype'][0] = etype

    if authorization_data is not None:
        req_body['enc-authorization-data'] = None
        req_body['enc-authorization-data']['etype'] = authorization_data[0]
        req_body['enc-authorization-data']['cipher'] = authorization_data[1]

    return req_body

def build_authenticator(realm, name, chksum, subkey, current_time, authorization_data=None):
    auth = Authenticator()

    auth['authenticator-vno'] = 5

    auth['crealm'] = realm

    auth['cname'] = None
    auth['cname']['name-type'] = NT_PRINCIPAL
    auth['cname']['name-string'] = None
    auth['cname']['name-string'][0] = name

    auth['cksum'] = None
    auth['cksum']['cksumtype'] = chksum[0]
    auth['cksum']['checksum'] = chksum[1]

    gt, ms = epoch2gt(current_time, microseconds=True)
    auth['cusec'] = ms
    auth['ctime'] = gt

    auth['subkey'] = None
    auth['subkey']['keytype'] = subkey[0]
    auth['subkey']['keyvalue'] = subkey[1]

    if authorization_data is not None:
        auth['authorization-data'] = _v(8, authorization_data)

    return auth

def build_ap_req(tgt, key, msg_type, authenticator):
    enc_auth = encrypt(key[0], key[1], msg_type, encode(authenticator))

    ap_req = AP_REQ()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req['ap-options'] = "'00000000000000000000000000000000'B"

    bla = Ticket()
    bla["tkt-vno"] = tgt["tkt-vno"]
    bla["realm"] = tgt["realm"]
    bla["sname"] = tgt["sname"]
    bla["enc-part"] = tgt["enc-part"]

    ap_req['ticket'] = _v(3, bla)

    ap_req['authenticator'] = None
    ap_req['authenticator']['etype'] = key[0]
    ap_req['authenticator']['cipher'] = enc_auth

    return ap_req

def build_tgs_req(target_realm, target_service, target_host,
                  user_realm, user_name, tgt, session_key, subkey,
                  nonce, current_time, authorization_data=None, pac_request=None):

    if authorization_data is not None:
        ad1 = AuthorizationData()
        ad1[0] = None
        ad1[0]['ad-type'] = authorization_data[0]
        ad1[0]['ad-data'] = authorization_data[1]
        ad = AuthorizationData()
        ad[0] = None
        ad[0]['ad-type'] = AD_IF_RELEVANT
        ad[0]['ad-data'] = encode(ad1)
        enc_ad = (subkey[0], encrypt(subkey[0], subkey[1], 5, encode(ad)))
    else:
        ad = None
        enc_ad = None

    req_body = build_req_body(target_realm, target_service, target_host, nonce, authorization_data=enc_ad)
    chksum = (RSA_MD5, checksum(RSA_MD5, encode(req_body)))

    authenticator = build_authenticator(user_realm, user_name, chksum, subkey, current_time)#, ad)
    ap_req = build_ap_req(tgt, session_key, 7, authenticator)

    tgs_req = TGS_REQ()
    tgs_req['pvno'] = 5
    tgs_req['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

    tgs_req['padata'] = None
    tgs_req['padata'][0] = None
    tgs_req['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgs_req['padata'][0]['padata-value'] = encode(ap_req)

    if pac_request is not None:
        pa_pac_request = KerbPaPacRequest()
        pa_pac_request['include-pac'] = pac_request
        tgs_req['padata'][1] = None
        tgs_req['padata'][1]['padata-type'] = 128
        tgs_req['padata'][1]['padata-value'] = encode(pa_pac_request)

    tgs_req['req-body'] = _v(4, req_body)

    return tgs_req

def build_pa_enc_timestamp(current_time, key):
    gt, ms = epoch2gt(current_time, microseconds=True)
    pa_ts_enc = PA_ENC_TS_ENC()
    pa_ts_enc['patimestamp'] = gt
    pa_ts_enc['pausec'] = ms

    pa_ts = PA_ENC_TIMESTAMP()
    pa_ts['etype'] = key[0]
    pa_ts['cipher'] = encrypt(key[0], key[1], 1, encode(pa_ts_enc))

    return pa_ts

def build_as_req(target_realm, user_name, key, current_time, nonce, pac_request=None):
    req_body = build_req_body(target_realm, 'krbtgt', '', nonce, cname=user_name)
    pa_ts = build_pa_enc_timestamp(current_time, key)

    as_req = AS_REQ()

    as_req['pvno'] = 5
    as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    as_req['padata'] = None
    as_req['padata'][0] = None
    as_req['padata'][0]['padata-type'] = 2
    as_req['padata'][0]['padata-value'] = encode(pa_ts)

    if pac_request is not None:
        pa_pac_request = KERB_PA_PAC_REQUEST()
        pa_pac_request['include-pac'] = pac_request
        as_req['padata'][1] = None
        as_req['padata'][1]['padata-type'] = 128
        as_req['padata'][1]['padata-value'] = encode(pa_pac_request)

    as_req['req-body'] = _v(4, req_body)

    return as_req

def send_req(req, kdc, port=88):
    data = encode(req)
    data = pack('>I', len(data)) + data
    sock = socket()
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            if datalen is None:
                datalen = unpack('>I', rep[:4])[0]
            if len(data) >= 4 + datalen:
                sock.close()
                return data[4:4 + datalen]

def _decrypt_rep(data, key, spec, enc_spec, msg_type):
    rep = decode(data, asn1Spec=spec)[0]
    rep_enc = str(rep['enc-part']['cipher'])
    #print rep_enc
    rep_enc = decrypt(key[0], key[1], msg_type, rep_enc)

    # MAGIC
    if rep_enc[:20] == '31337313373133731337':
        return rep_enc[20:22], None

    rep_enc = decode(rep_enc, asn1Spec=enc_spec)[0]

    return rep, rep_enc

def decrypt_tgs_rep(data, key):
    try:
        packet = decode(data, asn1Spec=KRB_ERROR())[0]
    except:
        return _decrypt_rep(data, key, TGS_REP(), EncTGSRepPart(), 9) # assume subkey
    else:  # packet contains an error
        try:
            error_code = decode(str(packet['e-data']), asn1Spec=KERB_ERROR_DATA())[0]
        except pyasn1.error.SubstrateUnderrunError:
            err = "An unknown error happend during packet parsing (bad SPN?)"
        else:
            nt_error = unpack('<L', str(error_code['data-value'])[:4])[0]

            try:
                err = "NT ERROR: %s(%s)" % nt_errors.ERROR_MESSAGES[nt_error]
            except IndexError:
                err = "An unknown error happend (packet is not a TGS-REP)"

        return "error", err

def _extract_data(data, spec):
    rep = decode(data, asn1Spec=spec)[0]
    return rep

#used in implicit authentication
def extract_tgs_data(data):
    return _extract_data(data, Ticket())

def decrypt_as_rep(data, key):
    return _decrypt_rep(data, key, AS_REP(), EncASRepPart(), 8)

def decrypt_ticket_enc_part(ticket, key):
    ticket_enc = str(ticket['enc-part']['cipher'])
    ticket_enc = decrypt(key[0], key[1], 2, ticket_enc)
    return decode(ticket_enc, asn1Spec=EncTicketPart())[0]

def iter_authorization_data(ad):
    if ad is None:
        return
    for block in ad:
        yield block
        if block['ad-type'] == AD_IF_RELEVANT:
            for subblock in iter_authorization_data(decode(str(block['ad-data']), asn1Spec=AuthorizationData())[0]):
                yield subblock
