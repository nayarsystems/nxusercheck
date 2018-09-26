package nxusercheck

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/jaracil/ei"

	nx "github.com/nayarsystems/nxgo/nxcore"
)

type UsersCheck struct {
	nexusConn             *nx.NexusConn
	Prefix                string       `json:"prefix"`
	OnlySubUsers          bool         `json:"onlySubUsers"`
	Templates             []string     `json:"templates"`
	AllowExtraTemplates   bool         `json:"allowExtraTemplates"`
	Permissions           *Permissions `json:"permissions"`
	AllowExtraPermissions bool         `json:"allowExtraPermissions"`
	Tags                  *Tags        `json:"tags"`
	AllowExtraTags        bool         `json:"allowExtraTags"`

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
	apply                 bool
	AllowExtraTemplates   bool
	AllowExtraPermissions bool
	AllowExtraTags        bool
}

func (uc *UsersCheck) Check(nc *nx.NexusConn, opts ...*CheckOpts) (error, error) {
	opt := &CheckOpts{}
	if len(opts) > 0 {
		opt = opts[0]
	}

	uc.init(nc)

	opt.apply = false

	return uc.check(opt)
}

func (uc *UsersCheck) Apply(nc *nx.NexusConn, opts ...*CheckOpts) (error, error) {
	opt := &CheckOpts{}
	if len(opts) > 0 {
		opt = opts[0]
	}

	uc.init(nc)

	opt.apply = true

	return uc.check(opt)
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

func (uc *UsersCheck) check(opts *CheckOpts) (error, error) {
	listOpts := &nx.ListOpts{}
	if !uc.OnlySubUsers {
		listOpts.LimitByDepth = true
		listOpts.Depth = 0
	}

	users, err := uc.nexusConn.UserList(uc.Prefix, 0, 0, listOpts)
	if err != nil {
		return nil, fmt.Errorf("Error listing users on %s: %s", uc.Prefix, err.Error())
	}

	checkErrs := []string{}

	done := 0
	for _, user := range users {
		if uc.OnlySubUsers == (user.User != uc.Prefix) {
			checkErr, applyErr := uc.checkUser(&user, opts)
			if checkErr != nil {
				checkErrs = append(checkErrs, checkErr.Error())
			}
			if opts.apply && applyErr != nil {
				return fmt.Errorf(strings.Join(checkErrs, "\n")), applyErr
			}
			done++
		}
	}

	if done == 0 {
		return nil, fmt.Errorf("Error listing users on %s: no users found", uc.Prefix)
	}

	if len(checkErrs) != 0 {
		return fmt.Errorf(strings.Join(checkErrs, "\n")), nil
	}
	return nil, nil
}

func (uc *UsersCheck) checkUser(userInfo *nx.UserInfo, opts *CheckOpts) (error, error) {
	// Check templates
	var applyErr error
	outs := []string{}

	if uc.Templates != nil {
		if opts.AllowExtraTemplates || uc.AllowExtraTemplates {
			if missing, ok := checkTemplatesOrderMatch(userInfo.Templates, uc.Templates); !ok {
				outs = append(outs, fmt.Sprintf("\tWRONG TEMPLATES:\n\n\t* Has: %v\n\t* Wants in order: %v\n", userInfo.Templates, uc.Templates))
				if opts.apply {
					if err := applyTemplates(uc.nexusConn, userInfo, append(userInfo.Templates, missing...)); err != nil {
						applyErr = fmt.Errorf("Error applying templates to %s: %s", userInfo.User, err.Error())
					}
				}
			}
		} else {
			if !checkTemplatesExactMatch(userInfo.Templates, uc.Templates) {
				outs = append(outs, fmt.Sprintf("\tWRONG TEMPLATES:\n\n\t* Has: %v\n\t* Wants exactly: %v\n", userInfo.Templates, uc.Templates))
				if opts.apply {
					if err := applyTemplates(uc.nexusConn, userInfo, uc.Templates); err != nil {
						applyErr = fmt.Errorf("Error applying templates to %s: %s", userInfo.User, err.Error())
					}
				}
			}
		}
		/* missing, ok := checkTemplatesAnyOrder(userInfo.Templates, uc.Templates) */
	}

	// Check tags
	if uc.Tags != nil {
		if opts.AllowExtraTags || uc.AllowExtraTags {
			if wrong, missing, ok := checkTags(userInfo.Tags, uc.fullTags); !ok {
				outs = append(outs, formatTagErrors(wrong, missing, nil))
				if opts.apply && applyErr == nil {
					if err := applyTags(uc.nexusConn, userInfo, wrong, missing, nil); err != nil {
						applyErr = fmt.Errorf("Error applying tags to %s: %s", userInfo.User, err.Error())
					}
				}
			}
		} else {
			if wrong, missing, extra, ok := checkTagsExactMatch(userInfo.Tags, uc.fullTags); !ok {
				outs = append(outs, formatTagErrors(wrong, missing, extra))
				if opts.apply && applyErr == nil {
					if err := applyTags(uc.nexusConn, userInfo, wrong, missing, extra); err != nil {
						applyErr = fmt.Errorf("Error applying tags to %s: %s", userInfo.User, err.Error())
					}
				}
			}
		}
	}

	// Check perms
	if uc.Permissions != nil {
		if opts.AllowExtraPermissions || uc.AllowExtraPermissions {
			if wrong, missing, ok := checkPerms(userInfo.Tags, uc.fullPermissions); !ok {
				outs = append(outs, formatPermErrors(wrong, missing, nil))
				if opts.apply && applyErr == nil {
					if err := applyTags(uc.nexusConn, userInfo, wrong, missing, nil); err != nil {
						applyErr = fmt.Errorf("Error applying permissions to %s: %s", userInfo.User, err.Error())
					}
				}
			}
		} else {
			if wrong, missing, extra, ok := checkPermsExactMatch(userInfo.Tags, uc.fullPermissions); !ok {
				outs = append(outs, formatPermErrors(wrong, missing, extra))
				if opts.apply && applyErr == nil {
					if err := applyTags(uc.nexusConn, userInfo, wrong, missing, extra); err != nil {
						applyErr = fmt.Errorf("Error applying permissions to %s: %s", userInfo.User, err.Error())
					}
				}
			}
		}
	}

	if len(outs) == 0 {
		return nil, nil
	} else if !opts.apply {
		return fmt.Errorf("%s check errors:\n\n%s", userInfo.User, strings.Join(outs, "\n")), nil
	} else if applyErr != nil {
		return fmt.Errorf("%s check errors:\n\n%s", userInfo.User, strings.Join(outs, "\n")), applyErr
	} else {
		outs = append(outs, fmt.Sprintf("%s all errors fixed", userInfo.User))
		return fmt.Errorf("%s check errors:\n\n%s", userInfo.User, strings.Join(outs, "\n")), nil
	}
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

func applyTemplates(nc *nx.NexusConn, userInfo *nx.UserInfo, templates []string) error {
	for _, tpl := range userInfo.Templates {
		if _, err := nc.UserDelTemplate(userInfo.User, tpl); err != nil {
			return err
		}
	}
	for _, tpl := range templates {
		if _, err := nc.UserAddTemplate(userInfo.User, tpl); err != nil {
			return err
		}
	}
	return nil
}

func applyTags(nc *nx.NexusConn, userInfo *nx.UserInfo, wrong map[string]map[string]interface{}, missing map[string]map[string]interface{}, extra map[string]map[string]interface{}) error {
	if wrong != nil {
		for prefix, tagval := range wrong {
			delTags := []string{}
			for tag := range tagval {
				delTags = append(delTags, tag)
			}
			if _, err := nc.UserDelTags(userInfo.User, prefix, delTags); err != nil {
				return err
			}
		}
	}
	if extra != nil {
		for prefix, tagval := range extra {
			delTags := []string{}
			for tag := range tagval {
				delTags = append(delTags, tag)
			}
			if _, err := nc.UserDelTags(userInfo.User, prefix, delTags); err != nil {
				return err
			}
		}
	}
	if missing != nil {
		for prefix, tagval := range missing {
			if _, err := nc.UserSetTags(userInfo.User, prefix, tagval); err != nil {
				return err
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

func checkTemplatesOrderMatch(has []string, wants []string) ([]string, bool) {
	i := 0
	for _, tpl := range has {
		if wants[i] == tpl {
			i++
		}
	}
	if len(wants) != i {
		return wants[i:], false
	}
	return nil, true
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
