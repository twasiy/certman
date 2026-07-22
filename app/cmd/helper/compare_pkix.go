// Copyright 2026 Tassok Imam Wasiy

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package helper

import (
	"crypto/x509/pkix"
	"reflect"
	"strings"
)

// Helper to exhaustively compare pkix.Name structs
func ComparePkixName(prefix string, n1, n2 pkix.Name, addDiff func(string, string, string)) {
	if n1.CommonName != n2.CommonName {
		addDiff(prefix+" CN", n1.CommonName, n2.CommonName)
	}
	if !reflect.DeepEqual(n1.Organization, n2.Organization) {
		addDiff(prefix+" Org (O)", strings.Join(n1.Organization, ", "), strings.Join(n2.Organization, ", "))
	}
	if !reflect.DeepEqual(n1.OrganizationalUnit, n2.OrganizationalUnit) {
		addDiff(prefix+" OU", strings.Join(n1.OrganizationalUnit, ", "), strings.Join(n2.OrganizationalUnit, ", "))
	}
	if !reflect.DeepEqual(n1.Country, n2.Country) {
		addDiff(prefix+" Country (C)", strings.Join(n1.Country, ", "), strings.Join(n2.Country, ", "))
	}
	if !reflect.DeepEqual(n1.Province, n2.Province) {
		addDiff(prefix+" State/Province (ST)", strings.Join(n1.Province, ", "), strings.Join(n2.Province, ", "))
	}
	if !reflect.DeepEqual(n1.Locality, n2.Locality) {
		addDiff(prefix+" Locality (L)", strings.Join(n1.Locality, ", "), strings.Join(n2.Locality, ", "))
	}
	if !reflect.DeepEqual(n1.StreetAddress, n2.StreetAddress) {
		addDiff(prefix+" Street Address", strings.Join(n1.StreetAddress, ", "), strings.Join(n2.StreetAddress, ", "))
	}
	if !reflect.DeepEqual(n1.PostalCode, n2.PostalCode) {
		addDiff(prefix+" Postal Code", strings.Join(n1.PostalCode, ", "), strings.Join(n2.PostalCode, ", "))
	}
}
