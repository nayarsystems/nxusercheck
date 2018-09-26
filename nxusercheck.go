package nxusercheck

import (
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/jaracil/ei"

	nx "github.com/nayarsystems/nxgo/nxcore"
)

type UsersCheck struct {
	nexusConn    *nx.NexusConn
	User         string       `json:"user"`
	OnlySubUsers bool         `json:"onlySubUsers"`
	Templates    []string     `json:"templates"`
	Permissions  *Permissions `json:"permissions"`
	Tags         *Tags        `json:"tags"`

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
	TemplatesExactMatch   bool
	TemplatesOrderMatch   bool
	TagsExactMatch        bool
	PermissionsExactMatch bool
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

	users, err := uc.nexusConn.UserList(uc.User, 0, 0, listOpts)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if uc.OnlySubUsers == (user.User != uc.User) {
			if err := uc.checkUser(&user, opts); err != nil {
				return err, nil
			}
		}
	}

	return nil, nil
}

func (uc *UsersCheck) apply(opts *ApplyOpts) (bool, error) {
	listOpts := &nx.ListOpts{}
	if !uc.OnlySubUsers {
		listOpts.LimitByDepth = true
		listOpts.Depth = 0
	}

	users, err := uc.nexusConn.UserList(uc.User, 0, 0, listOpts)
	if err != nil {
		return false, err
	}

	if opts.Clean {
		if uc.OnlySubUsers {
			log.Printf("Delete %d users on prefix %s", len(users), uc.User)
		}
		for _, user := range users {
			if uc.OnlySubUsers == (user.User != uc.User) {
				if _, err = uc.nexusConn.UserDelete(user.User); err != nil {
					return false, err
				}
				log.Printf("Deleted user %s", user.User)
			}
		}
	}

	for _, user := range users {
		if uc.OnlySubUsers == (user.User != uc.User) {
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
	// Check templates
	if uc.Templates != nil {
		if opts.TemplatesExactMatch {
			if !checkTemplatesExactMatch(userInfo.Templates, uc.Templates) {
				return fmt.Errorf("%s has incorrect templates:\n- Has:   %v\n+Wants exactly: %v", userInfo.User, userInfo.Templates, uc.Templates)
			}
		} else if opts.TemplatesOrderMatch {
			if !checkTemplatesOrderMatch(userInfo.Templates, uc.Templates) {
				return fmt.Errorf("%s has incorrect templates:\n- Has:   %v\n+Wants in order: %v", userInfo.User, userInfo.Templates, uc.Templates)
			}
		} else {
			if missing, ok := checkTemplatesAnyOrder(userInfo.Templates, uc.Templates); !ok {
				return fmt.Errorf("%s has incorrect templates:\n- Has:   %v\n+Wants in any order: %v\n  Missing: %v", userInfo.User, userInfo.Templates, uc.Templates, missing)
			}
		}
	}

	// Check tags
	if uc.Tags != nil {
		if opts.TagsExactMatch {
			if wrong, missing, extra, ok := checkTagsExactMatch(userInfo.Tags, uc.fullTags); !ok {
				return fmt.Errorf("%s has errors on tags:\n%s", userInfo.User, formatTagErrors(wrong, missing, extra))
			}
		} else {
			if wrong, missing, ok := checkTags(userInfo.Tags, uc.fullTags); !ok {
				return fmt.Errorf("%s has errors on tags:\n%s", userInfo.User, formatTagErrors(wrong, missing, nil))
			}
		}
	}

	// Check perms
	if uc.Permissions != nil {
		if opts.PermissionsExactMatch {
			if wrong, missing, extra, ok := checkPermsExactMatch(userInfo.Tags, uc.fullPermissions); !ok {
				return fmt.Errorf("%s has errors on permissions:\n%s", userInfo.User, formatPermErrors(wrong, missing, extra))
			}
		} else {
			if wrong, missing, ok := checkPerms(userInfo.Tags, uc.fullPermissions); !ok {
				return fmt.Errorf("%s has errors on permissions:\n%s", userInfo.User, formatPermErrors(wrong, missing, nil))
			}
		}
	}

	return nil
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

func addPrefTagVal(dest map[string]map[string]interface{}, prefix string, tag string, val interface{}) {
	if dest == nil {
		dest = map[string]map[string]interface{}{}
	}
	if _, ok := dest[prefix]; !ok {
		dest[prefix] = map[string]interface{}{}
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
