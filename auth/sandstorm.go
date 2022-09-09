package auth

import (
	"log"
	"net/http"
	"strings"

	"github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/files"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// MethodSandstormAuth is used to identify sandstorm auth.
const MethodSandstormAuth settings.AuthMethod = "sandstorm"

type sandstormCred struct {
	Username string `json:"username"`
}

// SandstormAuth is a sandstorm implementation of an Auther.
type SandstormAuth struct {
	Users    users.Store        `json:"-"`
	Settings *settings.Settings `json:"-"`
	Server   *settings.Server   `json:"-"`
	Cred     sandstormCred      `json:"-"`
	Fields   sandstormFields    `json:"-"`
}

// Auth authenticates the user via a json in content body.
func (a *SandstormAuth) Auth(r *http.Request, usr users.Store, stg *settings.Settings, srv *settings.Server) (*users.User, error) {
	var cred sandstormCred
	cred.Username = r.Header.Get("X-Sandstorm-User-Id")

	if cred.Username == "" {
		cred.Username = "__sandstorm_anonymous"
	}

	a.Users = usr
	a.Settings = stg
	a.Server = srv
	a.Cred = cred

	u, err := a.SaveUser()
	if err != nil {
		log.Println("Could not save user")
		log.Println(err)
		return nil, err
	}
	return u, nil
}

// LoginPage tells that sandstorm auth doesn't require a login page.
func (a *SandstormAuth) LoginPage() bool {
	return false
}

// SaveUser updates the existing user or creates a new one when not found
func (a *SandstormAuth) SaveUser() (*users.User, error) {
	u, err := a.Users.Get(a.Server.Root, a.Cred.Username)
	if err != nil && err != errors.ErrNotExist {
		return nil, err
	}

	if u == nil {

		// create user with the provided credentials
		d := &users.User{
			Username:     a.Cred.Username,
			Password:     "empty",
			Scope:        a.Settings.Defaults.Scope,
			Locale:       a.Settings.Defaults.Locale,
			ViewMode:     a.Settings.Defaults.ViewMode,
			SingleClick:  a.Settings.Defaults.SingleClick,
			Sorting:      a.Settings.Defaults.Sorting,
			Perm:         a.Settings.Defaults.Perm,
			Commands:     a.Settings.Defaults.Commands,
			HideDotfiles: a.Settings.Defaults.HideDotfiles,
		}
		u = a.GetUser(d)

		err = a.Users.Save(u)
		if err != nil {
			return nil, err
		}

		// Anonymous user
		return u, nil
	}

	return u, nil
}

// GetUser returns a User filled with sandstorm values or provided defaults
func (a *SandstormAuth) GetUser(d *users.User) *users.User {
	// adds all permissions when user is admin
	isAdmin := a.Fields.GetBoolean("user.perm.admin", d.Perm.Admin)
	perms := users.Permissions{
		Admin:    isAdmin,
		Execute:  isAdmin || a.Fields.GetBoolean("user.perm.execute", d.Perm.Execute),
		Create:   isAdmin || a.Fields.GetBoolean("user.perm.create", d.Perm.Create),
		Rename:   isAdmin || a.Fields.GetBoolean("user.perm.rename", d.Perm.Rename),
		Modify:   isAdmin || a.Fields.GetBoolean("user.perm.modify", d.Perm.Modify),
		Delete:   isAdmin || a.Fields.GetBoolean("user.perm.delete", d.Perm.Delete),
		Share:    isAdmin || a.Fields.GetBoolean("user.perm.share", d.Perm.Share),
		Download: isAdmin || a.Fields.GetBoolean("user.perm.download", d.Perm.Download),
	}
	user := users.User{
		ID:          d.ID,
		Username:    d.Username,
		Password:    d.Password,
		Scope:       a.Fields.GetString("user.scope", d.Scope),
		Locale:      a.Fields.GetString("user.locale", d.Locale),
		ViewMode:    users.ViewMode(a.Fields.GetString("user.viewMode", string(d.ViewMode))),
		SingleClick: a.Fields.GetBoolean("user.singleClick", d.SingleClick),
		Sorting: files.Sorting{
			Asc: a.Fields.GetBoolean("user.sorting.asc", d.Sorting.Asc),
			By:  a.Fields.GetString("user.sorting.by", d.Sorting.By),
		},
		Commands:     a.Fields.GetArray("user.commands", d.Commands),
		HideDotfiles: a.Fields.GetBoolean("user.hideDotfiles", d.HideDotfiles),
		Perm:         perms,
		LockPassword: true,
	}

	return &user
}

// sandstormFields is used to access fields from the sandstorm
type sandstormFields struct {
	Values map[string]string
}

// validSandstormFields contains names of the fields that can be used
var validSandstormFields = []string{
	"sandstorm.action",
	"user.scope",
	"user.locale",
	"user.viewMode",
	"user.singleClick",
	"user.sorting.by",
	"user.sorting.asc",
	"user.commands",
	"user.hideDotfiles",
	"user.perm.admin",
	"user.perm.execute",
	"user.perm.create",
	"user.perm.rename",
	"user.perm.modify",
	"user.perm.delete",
	"user.perm.share",
	"user.perm.download",
}

// IsValid checks if the provided field is on the valid fields list
func (hf *sandstormFields) IsValid(field string) bool {
	for _, val := range validSandstormFields {
		if field == val {
			return true
		}
	}

	return false
}

// GetString returns the string value or provided default
func (hf *sandstormFields) GetString(k, dv string) string {
	val, ok := hf.Values[k]
	if ok {
		return val
	}
	return dv
}

// GetBoolean returns the bool value or provided default
func (hf *sandstormFields) GetBoolean(k string, dv bool) bool {
	val, ok := hf.Values[k]
	if ok {
		return val == "true"
	}
	return dv
}

// GetArray returns the array value or provided default
func (hf *sandstormFields) GetArray(k string, dv []string) []string {
	val, ok := hf.Values[k]
	if ok && strings.TrimSpace(val) != "" {
		return strings.Split(val, " ")
	}
	return dv
}
