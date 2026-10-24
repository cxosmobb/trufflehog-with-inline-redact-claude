// Command lowpriv runs a command the way a standard, non-elevated Windows user
// runs it: without any privilege but SeChangeNotifyPrivilege, with the
// Administrators group set to deny-only, at medium integrity. The fork's CI
// uses it to show that `trufflehog redact --in-place` needs no privileges,
// although GitHub's Windows runners run as an administrator.
//
// Usage: go run ./hack/lowpriv <command> [args...]
//
// lowpriv -describe prints the privileges, Administrators membership and
// integrity level of its own token; check-token.ps1 runs it through lowpriv
// to inspect the restricted token from inside.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Flags of CreateRestrictedToken.
const (
	disableMaxPrivilege = 0x1
	luaToken            = 0x4
)

var createRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

func restrictedToken() (windows.Token, error) {
	var token windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_QUERY | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &token); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	deny := windows.SIDAndAttributes{Sid: admins}
	var restricted windows.Token
	if ok, _, err := createRestrictedToken.Call(uintptr(token), disableMaxPrivilege|luaToken,
		1, uintptr(unsafe.Pointer(&deny)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted))); ok == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", err)
	}

	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		return 0, err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		restricted.Close()
		return 0, fmt.Errorf("SetTokenInformation(TokenIntegrityLevel): %w", err)
	}

	// A token derived from an elevated one still makes Administrators the
	// owner of the objects (pipes, processes) its process creates, and grants
	// only Administrators and SYSTEM access to them. A standard user's token
	// names the user instead, without which the process could not even use
	// the pipes it creates.
	if err := ownObjectsAsUser(token, restricted); err != nil {
		restricted.Close()
		return 0, err
	}
	return restricted, nil
}

func ownObjectsAsUser(token, restricted windows.Token) error {
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	grant := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{grant(user.User.Sid), grant(system)}, nil)
	if err != nil {
		return err
	}
	owner := struct{ Owner *windows.SID }{user.User.Sid}
	if err := windows.SetTokenInformation(restricted, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner))); err != nil {
		return fmt.Errorf("SetTokenInformation(TokenOwner): %w", err)
	}
	defaultDACL := struct{ DefaultDacl *windows.ACL }{dacl}
	if err := windows.SetTokenInformation(restricted, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&defaultDACL)), uint32(unsafe.Sizeof(defaultDACL))); err != nil {
		return fmt.Errorf("SetTokenInformation(TokenDefaultDacl): %w", err)
	}
	return nil
}

// describe prints facts about this process's own token.
func describe() error {
	token := windows.GetCurrentProcessToken()
	buf, err := tokenInformation(token, windows.TokenPrivileges)
	if err != nil {
		return err
	}
	var changeNotify windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &changeNotify); err != nil {
		return err
	}
	others := 0
	for _, p := range (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0])).AllPrivileges() {
		if p.Luid != changeNotify {
			others++
		}
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	// A zero token checks the effective token of this thread, which is how
	// CheckTokenMembership accepts primary tokens.
	admin, err := windows.Token(0).IsMember(admins)
	if err != nil {
		return err
	}

	buf, err = tokenInformation(token, windows.TokenIntegrityLevel)
	if err != nil {
		return err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	integrity := label.SubAuthority(uint32(label.SubAuthorityCount()) - 1)

	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	buf, err = tokenInformation(token, windows.TokenOwner)
	if err != nil {
		return err
	}
	owner := (*struct{ Owner *windows.SID })(unsafe.Pointer(&buf[0])).Owner

	fmt.Printf("privileges_besides_change_notify=%d\nadministrator=%t\nintegrity=0x%04x\nowner_is_user=%t\n",
		others, admin, integrity, owner.Equals(user.User.Sid))
	return nil
}

func tokenInformation(t windows.Token, class uint32) ([]byte, error) {
	var n uint32
	_ = windows.GetTokenInformation(t, class, nil, 0, &n)
	if n == 0 {
		return nil, fmt.Errorf("GetTokenInformation(%d) returned no size", class)
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(t, class, &buf[0], n, &n); err != nil {
		return nil, err
	}
	return buf, nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-describe" {
		if err := describe(); err != nil {
			fmt.Fprintln(os.Stderr, "lowpriv:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lowpriv <command> [args...]")
		os.Exit(2)
	}
	token, err := restrictedToken()
	if err != nil {
		fmt.Fprintln(os.Stderr, "lowpriv:", err)
		os.Exit(1)
	}
	defer token.Close()

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// With a token and no Env, the child would get the token user's default
	// environment rather than this one.
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	err = cmd.Run()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		os.Exit(exit.ExitCode())
	case err != nil:
		fmt.Fprintln(os.Stderr, "lowpriv:", err)
		os.Exit(1)
	}
}
