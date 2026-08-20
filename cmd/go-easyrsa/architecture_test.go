package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var forbiddenProductionImports = map[string]bool{
	"crypto/ecdsa":                       true,
	"crypto/ed25519":                     true,
	"crypto/rand":                        true,
	"crypto/rsa":                         true,
	"crypto/x509":                        true,
	"encoding/pem":                       true,
	"github.com/gofrs/flock":             true,
	"go.mozilla.org/pkcs7":               true,
	"software.sslmate.com/src/go-pkcs12": true,
}

var forbiddenProductionDeclarations = map[string]bool{
	"writePKIArtifact":       true,
	"createRootTemp":         true,
	"withLifecycleSession":   true,
	"withPKIMutationLock":    true,
	"acquirePKIMutationLock": true,
	"lifecycleSession":       true,
	"stagedPKIMoves":         true,
}

func TestCLIProductionRemainsThinPKIAdapter(t *testing.T) {
	t.Parallel()

	fileSet := token.NewFileSet()
	err := filepath.WalkDir(".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if name != "." && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileSet, name, nil, 0)
		if err != nil {
			return err
		}
		require.Empty(t, thinAdapterViolations(name, file), name)
		return nil
	})
	require.NoError(t, err)
}

func TestThinAdapterGuardRejectsRenamedImplementationLogic(t *testing.T) {
	t.Parallel()

	fixtures := map[string]string{
		"renamed artifact writer": `package main
import "os"
func persistResult(name string, data []byte) error { return os.WriteFile(name, data, 0600) }`,
		"renamed ASN1 parser": `package main
import "encoding/asn1"
func decodeSubject(data []byte, out any) error { _, err := asn1.Unmarshal(data, out); return err }`,
		"alternate x509 parser": `package main
import "crypto/x509"
func decodeCertificates(data []byte) error { _, err := x509.ParseCertificates(data); return err }`,
	}
	for name, source := range fixtures {
		name, source := name, source
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), name+".go", source, 0)
			require.NoError(t, err)
			require.NotEmpty(t, thinAdapterViolations(name+".go", file))
		})
	}
}

func thinAdapterViolations(filename string, file *ast.File) []string {
	var violations []string
	importsByName := make(map[string]string)
	for _, imported := range file.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			violations = append(violations, fmt.Sprintf("%s has invalid import", filename))
			continue
		}
		if forbiddenProductionImports[importPath] {
			violations = append(violations, fmt.Sprintf("%s imports forbidden implementation package %s", filename, importPath))
		}
		name := path.Base(importPath)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		importsByName[name] = importPath
	}

	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		packageName, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		importPath := importsByName[packageName.Name]
		switch importPath {
		case "encoding/asn1":
			violations = append(violations, fmt.Sprintf("%s calls forbidden ASN.1 function %s", filename, selector.Sel.Name))
		case "io":
			if selector.Sel.Name == "Copy" || selector.Sel.Name == "CopyN" || selector.Sel.Name == "ReadAll" {
				violations = append(violations, fmt.Sprintf("%s calls forbidden stream implementation %s", filename, selector.Sel.Name))
			}
		case "os":
			switch selector.Sel.Name {
			case "Getenv", "ReadFile", "Exit":
			default:
				violations = append(violations, fmt.Sprintf("%s calls forbidden filesystem mutation/open function os.%s", filename, selector.Sel.Name))
			}
		}
		return true
	})

	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if forbiddenProductionDeclarations[declaration.Name.Name] {
				violations = append(violations, fmt.Sprintf("%s declares forbidden implementation helper %s", filename, declaration.Name.Name))
			}
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if ok && forbiddenProductionDeclarations[typeSpec.Name.Name] {
					violations = append(violations, fmt.Sprintf("%s declares forbidden implementation type %s", filename, typeSpec.Name.Name))
				}
			}
		}
	}
	return violations
}
