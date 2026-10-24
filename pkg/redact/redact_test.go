package redact

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	const (
		awsID     = "AKIAQYLPMN5HFIQR7XYZ"
		awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY1"
		pem       = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n-----END RSA PRIVATE KEY-----"
		token     = "ghp_R2d2C3poBB8ExampleTokenValue0123456789"
	)
	b64 := base64.StdEncoding.EncodeToString

	tests := []struct {
		name     string
		input    string
		findings []Finding
		want     string
	}{
		{
			name:     "only the secret of a key pair is redacted",
			input:    "aws_access_key_id = " + awsID + "\naws_secret_access_key = " + awsSecret + "\n",
			findings: []Finding{{Raw: []byte(awsID), RawV2: []byte(awsID + ":" + awsSecret), SecretParts: map[string]string{"access_key_id": awsID, "secret_access_key": awsSecret}}},
			want:     "aws_access_key_id = " + awsID + "\naws_secret_access_key = REDACTED\n",
		},
		{
			name:     "plain token keeps its quotes",
			input:    `GITHUB_TOKEN="` + token + `" # ci`,
			findings: []Finding{{Raw: []byte(token), SecretParts: map[string]string{"key": token}}},
			want:     `GITHUB_TOKEN="REDACTED" # ci`,
		},
		{
			name:     "every copy of a secret is redacted",
			input:    token + "\n" + token,
			findings: []Finding{{Raw: []byte(token)}},
			want:     "REDACTED\nREDACTED",
		},
		{
			name:     "URI keeps user and host",
			input:    "DATABASE_URL=postgres://app:s3cr3tP4ssw0rd@db.internal:5432/app\n",
			findings: []Finding{{SecretParts: map[string]string{"connection_string": "postgres://app:s3cr3tP4ssw0rd@db.internal:5432/app"}}},
			want:     "DATABASE_URL=postgres://app:REDACTED@db.internal:5432/app\n",
		},
		{
			name:     "rebuilt URI falls back to its password",
			input:    "host=db.internal user=app password=s3cr3tP4ssw0rd dbname=app",
			findings: []Finding{{Raw: []byte("postgresql://app:s3cr3tP4ssw0rd@db.internal:5432"), SecretParts: map[string]string{"connection_string": "postgresql://app:s3cr3tP4ssw0rd@db.internal:5432"}}},
			want:     "host=db.internal user=app password=REDACTED dbname=app",
		},
		{
			name:     "still reported URI widens to its userinfo",
			input:    "postgres://app:REDACTED@db.internal:5432/app",
			findings: []Finding{{SecretParts: map[string]string{"connection_string": "postgres://app:REDACTED@db.internal:5432/app"}}},
			want:     "postgres://REDACTED@db.internal:5432/app",
		},
		{
			name:     "connection string keeps other fields",
			input:    "jdbc:sqlserver://db:1433;user=sa;password=Hunter2Hunter2!;encrypt=true",
			findings: []Finding{{SecretParts: map[string]string{"connection_string": "jdbc:sqlserver://db:1433;user=sa;password=Hunter2Hunter2!;encrypt=true"}}},
			want:     "jdbc:sqlserver://db:1433;user=sa;password=REDACTED;encrypt=true",
		},
		{
			name:  "still reported connection string field is widened",
			input: "Server=db;User Id=sa;Password=REDACTED;",
			findings: []Finding{{Raw: []byte("REDACTED"), RawV2: []byte("sqlserver://sa:REDACTED@db"),
				SecretParts: map[string]string{"password": "REDACTED", "host": "db", "user": "sa"}}},
			want: "Server=db;User Id=sa;REDACTED;",
		},
		{
			name:     "PEM keeps header and footer",
			input:    "key: |\n" + pem + "\n",
			findings: []Finding{{Raw: []byte(pem), PrimarySecret: pem}},
			want:     "key: |\n-----BEGIN RSA PRIVATE KEY-----\nREDACTED\n-----END RSA PRIVATE KEY-----\n",
		},
		{
			name:  "JSON document is redacted field by field",
			input: `{"type": "service_account", "client_email": "a@b.iam.gserviceaccount.com", "private_key": "` + strings.ReplaceAll(pem, "\n", `\n`) + `\n", "token_uri": "https://oauth2.googleapis.com/token"}`,
			findings: []Finding{{Raw: []byte("a@b.iam.gserviceaccount.com"),
				SecretParts: map[string]string{"key": `{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com","private_key":"` + strings.ReplaceAll(pem, "\n", `\n`) + `\n","token_uri":"https://oauth2.googleapis.com/token"}`}}},
			want: `{"type": "service_account", "client_email": "a@b.iam.gserviceaccount.com", "private_key": "-----BEGIN RSA PRIVATE KEY-----\nREDACTED\n-----END RSA PRIVATE KEY-----\n", "token_uri": "https://oauth2.googleapis.com/token"}`,
		},
		{
			name:     "base64 is redacted inside and re-encoded",
			input:    "auth: " + b64([]byte("Authorization: Bearer "+token)) + "\n",
			findings: []Finding{{Raw: []byte(token)}},
			want:     "auth: " + b64([]byte("Authorization: Bearer REDACTED")) + "\n",
		},
		{
			name:     "short secret without anchors inside base64",
			input:    "v=" + b64([]byte(`base_url: "https://api.example.com/v1?key=seugeupfknprstoe"`)),
			findings: []Finding{{Raw: []byte("seugeupfknprstoe"), SecretParts: map[string]string{"key": "seugeupfknprstoe"}}},
			want:     "v=" + b64([]byte(`base_url: "https://api.example.com/v1?key=REDACTED"`)),
		},
		{
			name:     "nested base64",
			input:    "v=" + b64([]byte(b64([]byte("url="+token)))),
			findings: []Finding{{Raw: []byte(token)}},
			want:     "v=" + b64([]byte(b64([]byte("url=REDACTED")))),
		},
		{
			name:     "escaped unicode",
			input:    `{"t": "ghp_` + token[4:] + `"}`,
			findings: []Finding{{Raw: []byte(token)}},
			want:     `{"t": "REDACTED"}`,
		},
		{
			name:     "HTML entities",
			input:    `<a href="https://x?k=1&amp;token=` + token + `&amp;v=2">x</a>`,
			findings: []Finding{{Raw: []byte(token)}},
			want:     `<a href="https://x?k=1&amp;token=REDACTED&amp;v=2">x</a>`,
		},
		{
			name:     "percent encoding",
			input:    "https://x/?key=" + strings.ReplaceAll(awsSecret, "/", "%2F") + "&id=1",
			findings: []Finding{{Raw: []byte(awsSecret)}},
			want:     "https://x/?key=REDACTED&id=1",
		},
		{
			name:     "value capped by the detector's pattern is extended to its token",
			input:    `url = "https://hooks.slack.com/services/T0A1B2C3D/B0A1B2C3D/abcdefghijklmnopqrstuvwxyz0123"`,
			findings: []Finding{{Raw: []byte("https://hooks.slack.com/services/T0A1B2C3D/B0A1B2C3D/abcdefghijklmnopqrstuvwxy")}},
			want:     `url = "REDACTED"`,
		},
		{
			name:  "placeholder password is not redacted elsewhere",
			input: "Look for `jdbc:postgresql://db/app?user=USERNAME&password=PASSWORD`.\nThen read `DOCKER_ENV_PASSWORD`.",
			findings: []Finding{{SecretParts: map[string]string{
				"connection_string": "jdbc:postgresql://db/app?user=USERNAME&password=PASSWORD`"}}},
			want: "Look for `jdbc:postgresql://db/app?user=USERNAME&password=REDACTED`.\nThen read `DOCKER_ENV_PASSWORD`.",
		},
		{
			name:     "closing quote matched by the detector is kept",
			input:    "Connect to `jdbc:postgresql://localhost:5432/app` first.",
			findings: []Finding{{SecretParts: map[string]string{"connection_string": "jdbc:postgresql://localhost:5432/app`"}}},
			want:     "Connect to `REDACTED` first.",
		},
		{
			name:     "base64 basic auth also redacts the password it encodes",
			input:    `{"username": "ci", "password": "s3cr3t-Passw0rd", "auth": "` + b64([]byte("ci:s3cr3t-Passw0rd")) + `"}`,
			findings: []Finding{{SecretParts: map[string]string{"auth": b64([]byte("ci:s3cr3t-Passw0rd")), "registry": "r"}}},
			want:     `{"username": "ci", "password": "REDACTED", "auth": "REDACTED"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, report := Redact([]byte(tt.input), tt.findings, Options{})
			if string(got) != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
			if len(report.Unredacted) > 0 || len(report.Residual) > 0 {
				t.Errorf("unredacted=%v residual=%v", report.Unredacted, report.Residual)
			}
		})
	}
}

func TestRedactUTF16(t *testing.T) {
	const secret = "sk_live_51HExampleExampleExample00"
	input := append([]byte{0xff, 0xfe}, toUTF16("STRIPE_KEY="+secret+"\r\nNEXT=1", encUTF16LE)...)
	got, report := Redact(input, []Finding{{Raw: []byte(secret)}}, Options{})
	want := append([]byte{0xff, 0xfe}, toUTF16("STRIPE_KEY=REDACTED\r\nNEXT=1", encUTF16LE)...)
	if !bytes.Equal(got, want) || len(report.Unredacted) > 0 {
		t.Fatalf("got %q, want %q (report %+v)", got, want, report)
	}
}

func TestRedactAnchorsShortSecrets(t *testing.T) {
	// "pa55wd" is too short to redact everywhere: only the copy next to the
	// rest of the credential goes.
	far := strings.Repeat("filler line\n", 200)
	input := "note: pa55wd is the example password\n" + far + "url = postgres://admin:pa55wd@db.example.com/app\n"
	f := Finding{Raw: []byte("pa55wd"), SecretParts: map[string]string{"password": "pa55wd", "host": "db.example.com", "username": "admin"}}
	got, _ := Redact([]byte(input), []Finding{f}, Options{})
	want := "note: pa55wd is the example password\n" + far + "url = postgres://admin:REDACTED@db.example.com/app\n"
	if string(got) != want {
		t.Fatalf("got\n%s", got)
	}
}

func TestRedactFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		finding Finding
	}{
		{"secret not in input", "nothing here", Finding{Raw: []byte("ghp_notpresent0123456789abcdef")}},
		{"detector reported identifiers only", "portal: acme.clickhelp.co", Finding{Raw: []byte("acme.clickhelp.co"), SecretParts: map[string]string{"url": "acme.clickhelp.co"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, report := Redact([]byte(tt.input), []Finding{tt.finding}, Options{})
			if string(got) != tt.input {
				t.Errorf("input changed to %q", got)
			}
			if len(report.Unredacted) != 1 {
				t.Errorf("finding not reported as unredacted: %+v", report)
			}
		})
	}
}

func TestRedactResidual(t *testing.T) {
	input := `{"client_secret": "REDACTED", "client_id": "123.apps.googleusercontent.com"}`
	f := Finding{Raw: []byte("123.apps.googleusercontent.com"), SecretParts: map[string]string{"client_secret": "REDACTED", "client_id": "123.apps.googleusercontent.com"}}
	got, report := Redact([]byte(input), []Finding{f}, Options{})
	if string(got) != input || len(report.Residual) != 1 || len(report.Unredacted) != 0 {
		t.Fatalf("got %q, report %+v", got, report)
	}
}

func TestRedactReplacement(t *testing.T) {
	const secret = "xoxb-2222222222-3333333333-ExampleExample01"
	got, _ := Redact([]byte("SLACK="+secret), []Finding{{Raw: []byte(secret)}}, Options{Replacement: "<redacted>"})
	if string(got) != "SLACK=<redacted>" {
		t.Fatalf("got %q", got)
	}
	got, _ = Redact([]byte("\x00SLACK="+secret), []Finding{{Raw: []byte(secret)}}, Options{PreserveLength: true})
	if want := "\x00SLACK=REDACTED" + strings.Repeat("*", len(secret)-8); string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRedactFile(t *testing.T) {
	const secret = "xoxb-2222222222-3333333333-ExampleExample01"
	dir := t.TempDir()
	text := filepath.Join(dir, "config.env")
	bin := filepath.Join(dir, "app.bin")
	if err := os.WriteFile(text, []byte("SLACK="+secret+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	binData := append([]byte{0x7f, 'E', 'L', 'F', 0, 0}, []byte(secret+"\x00tail")...)
	if err := os.WriteFile(bin, binData, 0o755); err != nil {
		t.Fatal(err)
	}
	findings := []Finding{{Raw: []byte(secret)}}

	res, err := RedactFile(text, findings, Options{}, false)
	if err != nil || !res.Changed || res.Written {
		t.Fatalf("dry run: %+v, %v", res, err)
	}
	if data, _ := os.ReadFile(text); !bytes.Contains(data, []byte(secret)) {
		t.Fatal("dry run modified the file")
	}

	if res, err = RedactFile(text, findings, Options{}, true); err != nil || !res.Written {
		t.Fatalf("redact: %+v, %v", res, err)
	}
	if data, _ := os.ReadFile(text); string(data) != "SLACK=REDACTED\n" {
		t.Fatalf("text file = %q", data)
	}

	if res, err = RedactFile(bin, findings, Options{}, true); err != nil || !res.Binary {
		t.Fatalf("binary: %+v, %v", res, err)
	}
	data, _ := os.ReadFile(bin)
	if len(data) != len(binData) || !bytes.Contains(data, []byte("REDACTED****")) || bytes.Contains(data, []byte(secret)) {
		t.Fatalf("binary file = %q", data)
	}
}

func TestRedactFileRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.env")
	link := filepath.Join(dir, "link.env")
	if err := os.WriteFile(target, []byte("TOKEN=ghp_R2d2C3poBB8ExampleTokenValue0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := RedactFile(link, []Finding{{Raw: []byte("ghp_R2d2C3poBB8ExampleTokenValue0123456789")}}, Options{}, true); err == nil {
		t.Fatal("redacted through a symlink")
	}
}

func TestIdentifierParts(t *testing.T) {
	for _, k := range []string{"username", "host", "access_key_id", "client_id", "URL"} {
		if !IsIdentifierPart(k) {
			t.Errorf("%s should be an identifier", k)
		}
	}
	for _, k := range []string{"key", "password", "secret_access_key", "client_secret", "token"} {
		if IsIdentifierPart(k) {
			t.Errorf("%s should be secret", k)
		}
	}
}

// fakeScan reports the same findings for every scan.
func fakeScan(byFile map[string][]Finding) ScanFunc {
	return func([]string) (*Collector, error) {
		c := NewCollector()
		for path, fs := range byFile {
			if _, err := os.Stat(path); err == nil {
				c.byFile[path] = fs
			}
		}
		return c, nil
	}
}

func TestRunStaysInsidePaths(t *testing.T) {
	const secret = "xoxb-2222222222-3333333333-ExampleExample01"
	inside, outside := t.TempDir(), t.TempDir()
	in, out := filepath.Join(inside, "in.env"), filepath.Join(outside, "out.env")
	for _, p := range []string{in, out} {
		if err := os.WriteFile(p, []byte("SLACK="+secret), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	findings := []Finding{{Raw: []byte(secret)}}
	scan := fakeScan(map[string][]Finding{in: findings, out: findings})

	res, err := Run([]string{inside}, scan, RunOptions{InPlace: true, MaxPasses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Unredactable[out]; !ok {
		t.Errorf("file outside the paths not reported as unredactable: %+v", res)
	}
	if data, _ := os.ReadFile(in); string(data) != "SLACK=REDACTED" {
		t.Errorf("file inside = %q", data)
	}
	if data, _ := os.ReadFile(out); string(data) != "SLACK="+secret {
		t.Errorf("file outside was modified: %q", data)
	}

	if _, err := Run([]string{inside}, scan, RunOptions{InPlace: true, MaxPasses: 1, RemoveUnredactable: true}); !errors.Is(err, ErrOutsideRoots) {
		t.Errorf("removing a file outside the paths: err = %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("file outside was removed: %v", err)
	}
}

func TestReadSameRejectsReplacedFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := root.Lstat("a")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSame(root, "b", info); err == nil {
		t.Fatal("read a different file than the one checked")
	}
	if data, links, err := readSame(root, "a", info); err != nil || string(data) != "a" || links != 1 {
		t.Fatalf("readSame = %q, %v", data, err)
	}
}

func TestRedactLargeInputFailsClosed(t *testing.T) {
	const plain, escaped = "ghp_R2d2C3poBB8ExampleTokenValue0123456789", "ghp_EscapedExampleTokenValue012345678901"
	var esc strings.Builder
	for _, r := range escaped {
		fmt.Fprintf(&esc, `\u%04x`, r)
	}
	input := strings.Repeat("x", maxViewInput) + "\na=" + plain + "\nb=\"" + esc.String() + "\"\n"
	got, report := Redact([]byte(input), []Finding{{Raw: []byte(plain)}, {Raw: []byte(escaped)}}, Options{})
	if !strings.Contains(string(got), "\na=REDACTED\n") {
		t.Error("plain secret not redacted")
	}
	if len(report.Unredacted) != 1 || report.Unredacted[0] != 1 {
		t.Errorf("escaped secret in an oversized input should be unredactable: %+v", report.Unredacted)
	}
}

func TestRunDoesNotFollowSymlinkedDirectories(t *testing.T) {
	const secret = "xoxb-2222222222-3333333333-ExampleExample01"
	inside, outside := t.TempDir(), t.TempDir()
	target := filepath.Join(outside, "out.env")
	if err := os.WriteFile(target, []byte("SLACK="+secret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := linkDir(outside, filepath.Join(inside, "link")); err != nil {
		t.Skipf("directory links unavailable: %v", err)
	}
	// The path is lexically inside, but resolves outside through the link.
	viaLink := filepath.Join(inside, "link", "out.env")
	scan := fakeScan(map[string][]Finding{viaLink: {{Raw: []byte(secret)}}})
	res, err := Run([]string{inside}, scan, RunOptions{InPlace: true, MaxPasses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Unredactable[viaLink]; !ok {
		t.Errorf("file behind a symlinked directory not reported as unredactable: %+v", res)
	}
	if data, _ := os.ReadFile(target); string(data) != "SLACK="+secret {
		t.Errorf("file outside was modified through a symlink: %q", data)
	}
}

// linkDir links dir at link: a symlink, or on Windows without the privilege
// to create one, a directory junction.
func linkDir(dir, link string) error {
	err := os.Symlink(dir, link)
	if err != nil && runtime.GOOS == "windows" {
		if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, dir).CombinedOutput(); jerr != nil {
			return fmt.Errorf("%v; junction: %v: %s", err, jerr, out)
		}
		return nil
	}
	return err
}
