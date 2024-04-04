package ui

import (
	"bytes"
	"fmt"
	html_template "html/template"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/prometheus/common/model"

	"github.com/sapcc/maia/pkg/keystone"
)

// ExecuteTemplate renders an HTML-template stored in web/templates/
func ExecuteTemplate(w http.ResponseWriter, req *http.Request, name string, keystoneDriver keystone.Driver, data interface{}) {
	text, err := getTemplate(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tmplFuncs := html_template.FuncMap{
		"since": func(t time.Time) time.Duration {
			return time.Since(t).Round(time.Millisecond)
		},
		"pathPrefix":   func() string { return "" },
		"buildVersion": func() string { return "0.1" },
		"stripLabels": func(lset model.LabelSet, labels ...model.LabelName) model.LabelSet {
			for _, ln := range labels {
				delete(lset, ln)
			}
			return lset
		},
		"userId":         func() string { return req.Header.Get("X-User-Id") },
		"userName":       func() string { return req.Header.Get("X-User-Name") },
		"projectName":    func() string { return req.Header.Get("X-Project-Name") },
		"projectId":      func() string { return req.Header.Get("X-Project-Id") },
		"domainName":     func() string { return req.Header.Get("X-Domain-Name") },
		"domainId":       func() string { return req.Header.Get("X-Domain-Id") },
		"userDomainName": func() string { return req.Header.Get("X-User-Domain-Name") },
		// "authRules": func() []string {
		//	 rules, ok := data.([]string)
		//	 if ok {
		//	 	return rules
		//	 }
		//	 return []string{}
		// },
		"childProjects": func() []string {
			children, err := keystoneDriver.ChildProjects(req.Header.Get("X-Project-Id"))
			if err != nil {
				return []string{}
			}
			return children
		},
		// return list of user's projects with monitoring role: name --> id
		"userProjects": func() map[string]string {
			result := map[string]string{}
			projects, err := keystoneDriver.UserProjects(req.Header.Get("X-User-Id"))
			if err == nil {
				for _, p := range projects {
					result[p.ProjectName] = p.ProjectID
				}
			}
			return result
		},
	}

	result, err := expandHTMLTemplate(name, text, data, tmplFuncs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = io.WriteString(w, result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func getTemplate(name string) (string, error) {
	baseTmpl, err := Asset("web/templates/_base.html")
	if err != nil {
		return "", fmt.Errorf("error reading base template: %w", err)
	}
	pageTmpl, err := Asset(filepath.Join("web/templates", name))
	if err != nil {
		return "", fmt.Errorf("error reading page template %s: %w", name, err)
	}
	return string(baseTmpl) + string(pageTmpl), nil
}

func expandHTMLTemplate(name, text string, data interface{}, funcMap html_template.FuncMap) (string, error) {
	tmpl := html_template.New(name).Funcs(funcMap)
	tmpl.Option("missingkey=zero")
	tmpl.Funcs(html_template.FuncMap{
		"tmpl": func(name string, data interface{}) (html_template.HTML, error) {
			var buffer bytes.Buffer
			err := tmpl.ExecuteTemplate(&buffer, name, data)
			return html_template.HTML(buffer.String()), err //nolint:gosec // this is the correct method for trusted templating
		},
	})
	tmpl, err := tmpl.Parse(text)
	if err != nil {
		return "", fmt.Errorf("error parsing template %v: %w", name, err)
	}
	var buffer bytes.Buffer
	err = tmpl.Execute(&buffer, data)
	if err != nil {
		return "", fmt.Errorf("error executing template %v: %w", name, err)
	}
	return buffer.String(), nil
}
