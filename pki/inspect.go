package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"time"

	"github.com/kemsta/go-easyrsa/v2/cert"
	"github.com/kemsta/go-easyrsa/v2/storage"
)

// ShowCert returns the certificate pair for the given name.
func (p *PKI) ShowCert(name string) (*cert.Pair, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) (*cert.Pair, error) { return bound.ShowCert(name) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	return p.storage.GetLastByName(name)
}

// ShowReq returns the stored certificate request for the given name.
// It validates the request structure but, like Easy-RSA's inspection command,
// deliberately does not verify the request signature.
func (p *PKI) ShowReq(name string) (*cert.CSR, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) (*cert.CSR, error) { return bound.ShowReq(name) })
	}
	if err := validateEntityName(name); err != nil {
		return nil, err
	}
	csrPEM, err := p.csrStorage.GetCSR(name)
	if err != nil {
		return nil, err
	}
	request := &cert.CSR{Name: name, CSRPEM: append([]byte(nil), csrPEM...)}
	if _, err := request.Request(); err != nil {
		return nil, err
	}
	return request, nil
}

// ShowEKU returns Easy-RSA's Extended Key Usage classification for the named
// certificate. Unknown classifications return their label with cert.ErrUnknownEKU.
func (p *PKI) ShowEKU(name string) (cert.EKUType, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) (cert.EKUType, error) { return bound.ShowEKU(name) })
	}
	pair, err := p.ShowCert(name)
	if err != nil {
		return "", err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return "", err
	}
	return cert.ClassifyEKU(certificate)
}

// CheckSerial returns a deep copy of the matching index entry. A nil entry and
// nil error mean that the serial is available.
func (p *PKI) CheckSerial(serial *big.Int) (*storage.IndexEntry, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) (*storage.IndexEntry, error) { return bound.CheckSerial(serial) })
	}
	if serial == nil {
		return nil, errors.New("pki: serial must not be nil")
	}
	if serial.Sign() < 0 {
		return nil, errors.New("pki: serial must not be negative")
	}
	entries, err := p.index.Query(storage.IndexFilter{})
	if err != nil {
		return nil, err
	}
	var match *storage.IndexEntry
	for i := range entries {
		if entries[i].Serial == nil {
			return nil, errors.New("pki: index entry has nil serial")
		}
		if entries[i].Serial.Cmp(serial) != 0 {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("pki: serial %s appears more than once in index", storage.HexSerial(serial))
		}
		cloned, err := cloneIndexEntry(entries[i])
		if err != nil {
			return nil, fmt.Errorf("pki: clone index entry for serial %s: %w", storage.HexSerial(serial), err)
		}
		match = &cloned
	}
	return match, nil
}

// ShowCRL returns the current Certificate Revocation List.
func (p *PKI) ShowCRL() (*x509.RevocationList, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) (*x509.RevocationList, error) { return bound.ShowCRL() })
	}
	return p.crlHolder.Get()
}

// ShowExpiring returns certificates expiring within withinDays days.
func (p *PKI) ShowExpiring(withinDays int) ([]*cert.Pair, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) ([]*cert.Pair, error) { return bound.ShowExpiring(withinDays) })
	}
	validStatus := storage.StatusValid
	entries, err := p.index.Query(storage.IndexFilter{Status: &validStatus})
	if err != nil {
		return nil, err
	}
	cutoff := addExactDays(time.Now(), withinDays)
	var pairs []*cert.Pair
	var errs []error
	for _, e := range entries {
		if e.ExpiresAt.Before(cutoff) {
			pair, err := p.storage.GetBySerial(e.Serial)
			if err != nil {
				errs = append(errs, fmt.Errorf("serial %s: %w", e.Serial.Text(16), err))
				continue
			}
			pairs = append(pairs, pair)
		}
	}
	return pairs, errors.Join(errs...)
}

// ShowRevoked returns all revoked certificate pairs.
func (p *PKI) ShowRevoked() ([]*cert.Pair, error) {
	if !p.bound() {
		return withView(p, func(bound *PKI) ([]*cert.Pair, error) { return bound.ShowRevoked() })
	}
	revokedStatus := storage.StatusRevoked
	entries, err := p.index.Query(storage.IndexFilter{Status: &revokedStatus})
	if err != nil {
		return nil, err
	}
	var pairs []*cert.Pair
	var errs []error
	for _, e := range entries {
		pair, err := p.storage.GetBySerial(e.Serial)
		if err != nil {
			errs = append(errs, fmt.Errorf("serial %s: %w", e.Serial.Text(16), err))
			continue
		}
		pairs = append(pairs, pair)
	}
	return pairs, errors.Join(errs...)
}

// VerifyCert verifies the certificate chain for the named certificate.
func (p *PKI) VerifyCert(name string) error {
	if !p.bound() {
		return withViewError(p, func(bound *PKI) error { return bound.VerifyCert(name) })
	}
	if err := validateEntityName(name); err != nil {
		return err
	}
	pair, err := p.storage.GetLastByName(name)
	if err != nil {
		return err
	}
	certificate, err := pair.Certificate()
	if err != nil {
		return err
	}

	caPair, err := p.storage.GetLastByName(p.config.CAName)
	if err != nil {
		return err
	}
	caCert, err := caPair.Certificate()
	if err != nil {
		return err
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	_, err = certificate.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return err
	}

	// Check CRL if available.
	crl, err := p.crlHolder.Get()
	if err != nil {
		return err
	}
	if len(crl.Signature) > 0 {
		if err := crl.CheckSignatureFrom(caCert); err != nil {
			return fmt.Errorf("pki: CRL signature verification failed: %w", err)
		}
		serial, err := pair.Serial()
		if err != nil {
			return err
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(serial) == 0 {
				return errors.New("pki: certificate is revoked")
			}
		}
	}
	return nil
}

func cloneIndexEntry(entry storage.IndexEntry) (storage.IndexEntry, error) {
	cloned := entry
	if entry.Serial != nil {
		cloned.Serial = new(big.Int).Set(entry.Serial)
	}
	subject, err := clonePKIXName(entry.Subject)
	if err != nil {
		return storage.IndexEntry{}, err
	}
	cloned.Subject = subject
	return cloned, nil
}

func clonePKIXName(name pkix.Name) (pkix.Name, error) {
	cloned := name
	cloned.Country = append([]string(nil), name.Country...)
	cloned.Organization = append([]string(nil), name.Organization...)
	cloned.OrganizationalUnit = append([]string(nil), name.OrganizationalUnit...)
	cloned.Locality = append([]string(nil), name.Locality...)
	cloned.Province = append([]string(nil), name.Province...)
	cloned.StreetAddress = append([]string(nil), name.StreetAddress...)
	cloned.PostalCode = append([]string(nil), name.PostalCode...)
	var err error
	cloned.Names, err = cloneAttributes(name.Names)
	if err != nil {
		return pkix.Name{}, fmt.Errorf("subject names: %w", err)
	}
	cloned.ExtraNames, err = cloneAttributes(name.ExtraNames)
	if err != nil {
		return pkix.Name{}, fmt.Errorf("subject extra names: %w", err)
	}
	return cloned, nil
}

func cloneAttributes(attributes []pkix.AttributeTypeAndValue) ([]pkix.AttributeTypeAndValue, error) {
	if attributes == nil {
		return nil, nil
	}
	cloned := make([]pkix.AttributeTypeAndValue, len(attributes))
	for i, attribute := range attributes {
		cloned[i] = attribute
		cloned[i].Type = append(asn1.ObjectIdentifier(nil), attribute.Type...)
		value, err := cloneAttributeValue(attribute.Value)
		if err != nil {
			return nil, fmt.Errorf("attribute %d (%s): %w", i, attribute.Type, err)
		}
		cloned[i].Value = value
	}
	return cloned, nil
}

type cloneVisit struct {
	typeOf   reflect.Type
	pointer  uintptr
	length   int
	capacity int
}

var (
	asn1RawValueType = reflect.TypeOf(asn1.RawValue{})
	bigIntType       = reflect.TypeOf(big.Int{})
	timeType         = reflect.TypeOf(time.Time{})
)

func cloneAttributeValue(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	cloned, err := cloneReflectValue(reflect.ValueOf(value), make(map[cloneVisit]reflect.Value))
	if err != nil {
		return nil, err
	}
	return cloned.Interface(), nil
}

func cloneReflectValue(value reflect.Value, seen map[cloneVisit]reflect.Value) (reflect.Value, error) {
	if !value.IsValid() {
		return value, nil
	}
	if value.Type() == timeType {
		return value, nil
	}
	if value.Type() == bigIntType {
		n := value.Interface().(big.Int)
		return reflect.ValueOf(*new(big.Int).Set(&n)), nil
	}
	if value.Type() == asn1RawValueType {
		raw := value.Interface().(asn1.RawValue)
		raw.Bytes = append([]byte(nil), raw.Bytes...)
		raw.FullBytes = append([]byte(nil), raw.FullBytes...)
		return reflect.ValueOf(raw), nil
	}

	switch value.Kind() {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128,
		reflect.String:
		return value, nil
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		inner, err := cloneReflectValue(value.Elem(), seen)
		if err != nil {
			return reflect.Value{}, err
		}
		cloned := reflect.New(value.Type()).Elem()
		cloned.Set(inner)
		return cloned, nil
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		visit := cloneVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if cloned, ok := seen[visit]; ok {
			return cloned, nil
		}
		cloned := reflect.New(value.Type().Elem())
		seen[visit] = cloned
		elem, err := cloneReflectValue(value.Elem(), seen)
		if err != nil {
			return reflect.Value{}, err
		}
		cloned.Elem().Set(elem)
		return cloned, nil
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		visit := cloneVisit{
			typeOf:   value.Type(),
			pointer:  value.Pointer(),
			length:   value.Len(),
			capacity: value.Cap(),
		}
		if cloned, ok := seen[visit]; ok {
			return cloned, nil
		}
		cloned := reflect.MakeSlice(value.Type(), value.Len(), value.Cap())
		seen[visit] = cloned
		sourceFull := value.Slice(0, value.Cap())
		clonedFull := cloned.Slice(0, cloned.Cap())
		for i := 0; i < sourceFull.Len(); i++ {
			elem, err := cloneReflectValue(sourceFull.Index(i), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			clonedFull.Index(i).Set(elem)
		}
		return cloned, nil
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		visit := cloneVisit{typeOf: value.Type(), pointer: value.Pointer()}
		if cloned, ok := seen[visit]; ok {
			return cloned, nil
		}
		cloned := reflect.MakeMapWithSize(value.Type(), value.Len())
		seen[visit] = cloned
		iter := value.MapRange()
		for iter.Next() {
			key, err := cloneReflectValue(iter.Key(), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			item, err := cloneReflectValue(iter.Value(), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			cloned.SetMapIndex(key, item)
		}
		return cloned, nil
	case reflect.Array:
		cloned := reflect.New(value.Type()).Elem()
		for i := 0; i < value.Len(); i++ {
			elem, err := cloneReflectValue(value.Index(i), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			cloned.Index(i).Set(elem)
		}
		return cloned, nil
	case reflect.Struct:
		cloned := reflect.New(value.Type()).Elem()
		cloned.Set(value)
		for i := 0; i < value.NumField(); i++ {
			fieldType := value.Type().Field(i)
			if fieldType.PkgPath != "" {
				if typeContainsMutableState(fieldType.Type, make(map[reflect.Type]bool)) {
					return reflect.Value{}, fmt.Errorf("cannot clone mutable unexported field %s.%s", value.Type(), fieldType.Name)
				}
				continue
			}
			field, err := cloneReflectValue(value.Field(i), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			cloned.Field(i).Set(field)
		}
		return cloned, nil
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		if value.IsNil() {
			return reflect.Zero(value.Type()), nil
		}
		return reflect.Value{}, fmt.Errorf("cannot clone mutable %s value", value.Kind())
	default:
		return reflect.Value{}, fmt.Errorf("cannot clone %s value", value.Kind())
	}
}

func typeContainsMutableState(valueType reflect.Type, visiting map[reflect.Type]bool) bool {
	if valueType == timeType {
		return false
	}
	if visiting[valueType] {
		return false
	}
	visiting[valueType] = true
	defer delete(visiting, valueType)

	switch valueType.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface,
		reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return true
	case reflect.Array:
		return typeContainsMutableState(valueType.Elem(), visiting)
	case reflect.Struct:
		for i := 0; i < valueType.NumField(); i++ {
			if typeContainsMutableState(valueType.Field(i).Type, visiting) {
				return true
			}
		}
	}
	return false
}

// UpdateDB scans issued certificates and marks expired ones as expired in the index.
func (p *PKI) UpdateDB() error {
	if !p.bound() {
		return withUpdateError(p, func(bound *PKI) error { return bound.UpdateDB() })
	}
	if isReadOnly(p.index) {
		return storage.ErrReadOnly
	}

	validStatus := storage.StatusValid
	entries, err := p.index.Query(storage.IndexFilter{Status: &validStatus})
	if err != nil {
		return err
	}
	now := time.Now()
	var errs []error
	for _, e := range entries {
		if e.ExpiresAt.Before(now) {
			if err := p.index.Update(e.Serial, storage.StatusExpired, time.Time{}, 0); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
