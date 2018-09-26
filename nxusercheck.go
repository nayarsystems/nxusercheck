package nxusercheck

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/jaracil/ei"

	nx "github.com/nayarsystems/nxgo/nxcore"
)

type UsersCheck struct {
	nexusConn        *nx.NexusConn
	Prefix           string       `json:"prefix"`
	OnlySubUsers     bool         `json:"onlySubUsers"`
	Templates        []string     `json:"templates"`
	TemplatesMatch   string       `json:"templatesMatch"`
	Permissions      *Permissions `json:"permissions"`
	PermissionsMatch string       `json:"permissionsMatch"`
	Tags             *Tags        `json:"tags"`
	TagsMatch        string       `json:"tagsMatch"`

	fullPermissions T
	fullTags        T
}

type Permissions struct {
	ByPrefix   P `json:"byPrefix"`
	OnPrefixes P `json:"onPrefixes"`
}

type P map[string]map[string]bool

type Tags struct {
	ByPrefix   T `json:"byPrefix"`
	OnPrefixes T `json:"onPrefixes"`
}

type T map[string]map[string]interface{}

type CheckOpts struct {
	TemplatesMatch   string
	PermissionsMatch string
	TagsMatch        string
}

type ApplyOpts struct {
	Clean bool
}

func (uc *UsersCheck) Check(nc *nx.NexusConn, opts ...*CheckOpts) (error, error) {
	opt := &CheckOpts{}
	if len(opts) > 0 {
		opt = opts[0]
	}

	uc.init(nc)

	return uc.check(opt)
}

func (uc *UsersCheck) check(opts *CheckOpts) (error, error) {
	listOpts := &nx.ListOpts{}
	if !uc.OnlySubUsers {
		listOpts.LimitByDepth = true
		listOpts.Depth = 0
	}

	users, err := uc.nexusConn.UserList(uc.Prefix, 0, 0, listOpts)
	if err != nil {
		return nil, err
	}

	done := 0
	for _, user := range users {
		if uc.OnlySubUsers == (user.User != uc.Prefix) {
			if err := uc.checkUser(&user, opts); err != nil {
				return err, nil
			}
			done += 1
		}
	}

	if done == 0 {
		return fmt.Errorf("No users found on prefix %s", uc.Prefix), nil
	}

	return nil, nil
}

func (uc *UsersCheck) apply(opts *ApplyOpts) (bool, error) {
	listOpts := &nx.ListOpts{}
	if !uc.OnlySubUsers {
		listOpts.LimitByDepth = true
		listOpts.Depth = 0
	}

	users, err := uc.nexusConn.UserList(uc.Prefix, 0, 0, listOpts)
	if err != nil {
		return false, err
	}

	if opts.Clean {
		if uc.OnlySubUsers {
			log.Printf("Delete %d users on prefix %s", len(users), uc.Prefix)
		}
		for _, user := range users {
			if uc.OnlySubUsers == (user.User != uc.Prefix) {
				if _, err = uc.nexusConn.UserDelete(user.User); err != nil {
					return false, err
				}
				log.Printf("Deleted user %s", user.User)
			}
		}
	}

	for _, user := range users {
		if uc.OnlySubUsers == (user.User != uc.Prefix) {
			log.Printf("Here we should apply user %s", user.User)
		}
	}

	return true, nil
}

func (uc *UsersCheck) init(nc *nx.NexusConn) {
	uc.nexusConn = nc
	uc.fullPermissions = map[string]map[string]interface{}{}
	uc.fullTags = map[string]map[string]interface{}{}
	for prefix, perms := range uc.Permissions.ByPrefix {
		for perm, value := range perms {
			if strings.HasPrefix(perm, "@") {
				addPrefPermVal(uc.fullPermissions, prefix, perm, value)
			}
		}
	}
	for perm, prefixes := range uc.Permissions.OnPrefixes {
		for prefix, value := range prefixes {
			if strings.HasPrefix(perm, "@") {
				addPrefPermVal(uc.fullPermissions, prefix, perm, value)
			}
		}
	}
	for prefix, tags := range uc.Tags.ByPrefix {
		for tag, value := range tags {
			if !strings.HasPrefix(tag, "@") {
				addPrefTagVal(uc.fullTags, prefix, tag, value)
			}
		}
	}
	for tag, prefixes := range uc.Tags.OnPrefixes {
		for prefix, value := range prefixes {
			if !strings.HasPrefix(tag, "@") {
				addPrefTagVal(uc.fullTags, prefix, tag, value)
			}
		}
	}
}

func (uc *UsersCheck) checkUser(userInfo *nx.UserInfo, opts *CheckOpts) error {
	templatesMatch := "yes"
	if opts.TemplatesMatch != "" {
		templatesMatch = opts.TemplatesMatch
	} else if uc.TemplatesMatch != "" {
		templatesMatch = uc.TemplatesMatch
	}

	permissionsMatch := "yes"
	if opts.PermissionsMatch != "" {
		permissionsMatch = opts.PermissionsMatch
	} else if uc.PermissionsMatch != "" {
		permissionsMatch = uc.PermissionsMatch
	}

	tagsMatch := "yes"
	if opts.TagsMatch != "" {
		tagsMatch = opts.TagsMatch
	} else if uc.TagsMatch != "" {
		tagsMatch = uc.TagsMatch
	}

	// Check templates
	errs := []string{}

	if uc.Templates != nil {
		if templatesMatch == "order" {
			if !checkTemplatesOrderMatch(userInfo.Templates, uc.Templates) {
				errs = append(errs, fmt.Sprintf("WRONG TEMPLATES:\n\n\t* Has: %v\n\t* Wants in order: %v", userInfo.Templates, uc.Templates))
			}
		} else if templatesMatch == "no" {
			if missing, ok := checkTemplatesAnyOrder(userInfo.Templates, uc.Templates); !ok {
				errs = append(errs, fmt.Sprintf("WRONG TEMPLATES:\n\n\t* Has: %v\n\t* Wants in any order: %v\n\t* Missing: %v", userInfo.Templates, uc.Templates, missing))
			}
		} else {
			if !checkTemplatesExactMatch(userInfo.Templates, uc.Templates) {
				errs = append(errs, fmt.Sprintf("WRONG TEMPLATES:\n\n\t* Has: %v\n\t* Wants exactly: %v", userInfo.Templates, uc.Templates))
			}
		}
	}

	// Check tags
	if uc.Tags != nil {
		if tagsMatch == "no" {
			if wrong, missing, ok := checkTags(userInfo.Tags, uc.fullTags); !ok {
				errs = append(errs, formatTagErrors(wrong, missing, nil))
			}
		} else {
			if wrong, missing, extra, ok := checkTagsExactMatch(userInfo.Tags, uc.fullTags); !ok {
				errs = append(errs, formatTagErrors(wrong, missing, extra))
			}
		}
	}

	// Check perms
	if uc.Permissions != nil {
		if permissionsMatch == "no" {
			if wrong, missing, ok := checkPerms(userInfo.Tags, uc.fullPermissions); !ok {
				errs = append(errs, formatPermErrors(wrong, missing, nil))
			}
		} else {
			if wrong, missing, extra, ok := checkPermsExactMatch(userInfo.Tags, uc.fullPermissions); !ok {
				errs = append(errs, formatPermErrors(wrong, missing, extra))
			}
		}
	}

	if len(errs) != 0 {
		return fmt.Errorf("%s has errors:\n\n%s", userInfo.User, strings.Join(errs, "\n"))
	}
	return nil
}

func formatTagErrors(wrong, missing, extra map[string]map[string]interface{}) string {
	ls := []string{}
	if len(wrong) != 0 {
		ls = append(ls, "\tWRONG TAGS:\n")
		for prefix, tagval := range wrong {
			ls = append(ls, fmt.Sprintf("\t* %s", prefix))
			for tag, value := range tagval {
				ls = append(ls, fmt.Sprintf("\t\t- %s: wants %v has %v", tag, missing[prefix][tag], value))
			}
		}
		ls = append(ls, "")
	}
	if len(missing) != 0 {
		ls = append(ls, "\tMISSING TAGS:\n")
		for prefix, tagval := range missing {
			ls = append(ls, fmt.Sprintf("\t* %s", prefix))
			for tag, value := range tagval {
				if wrong[prefix] == nil || wrong[prefix][tag] == nil {
					ls = append(ls, fmt.Sprintf("\t\t- %s: wants %v", tag, value))
				}
			}
			ls = append(ls, "")
		}
	}
	if len(extra) != 0 {
		ls = append(ls, "\tEXTRA TAGS:\n")
		for prefix, tagval := range extra {
			ls = append(ls, fmt.Sprintf("\t* %s", prefix))
			for tag, value := range tagval {
				ls = append(ls, fmt.Sprintf("\t\t- %s: has %v", tag, value))
			}
			ls = append(ls, "")
		}
	}
	return strings.Join(ls, "\n")
}

func formatPermErrors(wrong, missing, extra map[string]map[string]interface{}) string {
	ls := []string{}
	if len(wrong) != 0 {
		ls = append(ls, "\tWRONG PERMISSIONS:\n")
		for prefix, tagval := range wrong {
			ls = append(ls, fmt.Sprintf("\t* %s", prefix))
			for tag, value := range tagval {
				ls = append(ls, fmt.Sprintf("\t\t- %s: wants %v has %v", tag, ei.N(missing[prefix][tag]).BoolZ(), ei.N(value).BoolZ()))
			}
			ls = append(ls, "")
		}
	}
	if len(missing) != 0 {
		ls = append(ls, "\tMISSING PERMISSIONS:\n")
		for prefix, tagval := range missing {
			ls = append(ls, fmt.Sprintf("\t* %s", prefix))
			for tag, value := range tagval {
				if wrong[prefix] == nil || wrong[prefix][tag] == nil {
					ls = append(ls, fmt.Sprintf("\t\t- %s: wants %v", tag, ei.N(value).BoolZ()))
				}
			}
			ls = append(ls, "")
		}
	}
	if len(extra) != 0 {
		ls = append(ls, "\tEXTRA PERMISSIONS:\n")
		for prefix, tagval := range extra {
			ls = append(ls, fmt.Sprintf("\t* %s", prefix))
			for tag, value := range tagval {
				ls = append(ls, fmt.Sprintf("\t\t- %s: has %v", tag, ei.N(value).BoolZ()))
			}
			ls = append(ls, "")
		}
	}
	return strings.Join(ls, "\n")
}

func checkTemplatesExactMatch(has []string, wants []string) bool {
	if len(has) != len(wants) {
		return false
	}
	for i, _ := range has {
		if has[i] != wants[i] {
			return false
		}
	}
	return true
}

func checkTemplatesOrderMatch(has []string, wants []string) bool {
	i := 0
	for _, tpl := range has {
		if wants[i] == tpl {
			i++
		}
	}
	if len(wants) != i {
		return false
	}
	return true
}

func checkTemplatesAnyOrder(has []string, wants []string) ([]string, bool) {
	missing := []string{}
	for _, tpl := range wants {
		found := false
		for _, tplHas := range has {
			if tplHas == tpl {
				found = true
			}
		}
		if !found {
			missing = append(missing, tpl)
		}
	}
	if len(missing) != 0 {
		return missing, false
	}
	return nil, true
}

func checkTagsExactMatch(has map[string]map[string]interface{}, wants map[string]map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, map[string]map[string]interface{}, bool) {
	hasTags := getTagsOnly(has)
	wrong, missing, extra := checkTagsWithDeepEqual(hasTags, wants)
	return wrong, missing, extra, (len(missing) == 0 && len(extra) == 0)
}

func checkTags(has map[string]map[string]interface{}, wants map[string]map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, bool) {
	hasTags := getTagsOnly(has)
	wrong, missing, _ := checkTagsWithDeepEqual(hasTags, wants)
	return wrong, missing, len(missing) == 0
}

func checkPermsExactMatch(has map[string]map[string]interface{}, wants map[string]map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, map[string]map[string]interface{}, bool) {
	hasPerms := getPermsOnly(has)
	wrong, missing, extra := checkTagsAsPerms(hasPerms, wants)
	return wrong, missing, extra, (len(missing) == 0 && len(extra) == 0)
}

func checkPerms(has map[string]map[string]interface{}, wants map[string]map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, bool) {
	hasPerms := getPermsOnly(has)
	wrong, missing, _ := checkTagsAsPerms(hasPerms, wants)
	return wrong, missing, len(missing) == 0
}

func checkTagsAsPerms(has map[string]map[string]interface{}, wants map[string]map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, map[string]map[string]interface{}) {
	return checkTagsWithFunc(has, wants, func(hval interface{}, wval interface{}) bool {
		return ei.N(hval).BoolZ() == ei.N(wval).BoolZ()
	})
}

func checkTagsWithDeepEqual(has map[string]map[string]interface{}, wants map[string]map[string]interface{}) (map[string]map[string]interface{}, map[string]map[string]interface{}, map[string]map[string]interface{}) {
	return checkTagsWithFunc(has, wants, func(hval interface{}, wval interface{}) bool {
		return reflect.DeepEqual(hval, wval)
	})
}

func checkTagsWithFunc(has map[string]map[string]interface{}, wants map[string]map[string]interface{}, f func(hval interface{}, wval interface{}) bool) (map[string]map[string]interface{}, map[string]map[string]interface{}, map[string]map[string]interface{}) {
	wrong := map[string]map[string]interface{}{}
	missing := map[string]map[string]interface{}{}
	extra := map[string]map[string]interface{}{}

	for hprefix, htagval := range has {
		for htag, hvalue := range htagval {
			if wtagval, ok := wants[hprefix]; !ok {
				addPrefTagVal(extra, hprefix, htag, hvalue)
			} else if _, ok := wtagval[htag]; !ok {
				addPrefTagVal(extra, hprefix, htag, hvalue)
			}
		}
	}
	for wprefix, wtagval := range wants {
		for wtag, wvalue := range wtagval {
			if htagval, ok := has[wprefix]; !ok {
				addPrefTagVal(missing, wprefix, wtag, wvalue)
			} else if hvalue, ok := htagval[wtag]; !ok {
				addPrefTagVal(missing, wprefix, wtag, wvalue)
			} else if !f(hvalue, wvalue) {
				addPrefTagVal(missing, wprefix, wtag, wvalue)
				addPrefTagVal(wrong, wprefix, wtag, hvalue)
			}
		}
	}

	return wrong, missing, extra
}

func getTagsOnly(tags map[string]map[string]interface{}) map[string]map[string]interface{} {
	tagsOnly := map[string]map[string]interface{}{}
	for prefix, tagval := range tags {
		for tag, value := range tagval {
			if !strings.HasPrefix(tag, "@") {
				addPrefTagVal(tagsOnly, prefix, tag, value)
			}
		}
	}
	return tagsOnly
}

func getPermsOnly(tags map[string]map[string]interface{}) map[string]map[string]interface{} {
	permsOnly := map[string]map[string]interface{}{}
	for prefix, tagval := range tags {
		for tag, value := range tagval {
			if strings.HasPrefix(tag, "@") {
				addPrefTagVal(permsOnly, prefix, tag, value)
			}
		}
	}
	return permsOnly
}

func addPrefTagVal(dest map[string]map[string]interface{}, prefix string, tag string, val interface{}) {
	if dest == nil {
		dest = map[string]map[string]interface{}{}
	}
	if _, ok := dest[prefix]; !ok {
		dest[prefix] = map[string]interface{}{}
	}
	sval, err := json.Marshal(val)
	if err != nil {
		panic(err.Error())
	}
	if err = json.Unmarshal(sval, &val); err != nil {
		panic(err.Error())
	}

	dest[prefix][tag] = val
}

func addPrefPermVal(dest map[string]map[string]interface{}, prefix string, perm string, val bool) {
	if dest == nil {
		dest = map[string]map[string]interface{}{}
	}
	if _, ok := dest[prefix]; !ok {
		dest[prefix] = map[string]interface{}{}
	}
	dest[prefix][perm] = val
}
