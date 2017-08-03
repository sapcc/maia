package ui

import (
	"bytes"
	"fmt"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/web/ui"
	html_template "html/template"
	"io"
	"net/http"
	"path/filepath"
	"time"
)

// ExecuteTemplate renders an HTML-template stored in web/templates/
func ExecuteTemplate(w http.ResponseWriter, req *http.Request, name string, data interface{}) {
	text, err := getTemplate(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	tmplFuncs := html_template.FuncMap{
		"since": func(t time.Time) time.Duration {
			return time.Since(t) / time.Millisecond * time.Millisecond
		},
		"pathPrefix":   func() string { return "" },
		"buildVersion": func() string { return "0.1" },
		"stripLabels": func(lset model.LabelSet, labels ...model.LabelName) model.LabelSet {
			for _, ln := range labels {
				delete(lset, ln)
			}
			return lset
		},
	}

	result, err := expandHTMLTemplate(name, text, data, tmplFuncs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, result)
}

func getTemplate(name string) (string, error) {
	baseTmpl, err := ui.Asset("web/templates/_base.html")
	if err != nil {
		return "", fmt.Errorf("error reading base template: %s", err)
	}
	pageTmpl, err := ui.Asset(filepath.Join("web/templates", name))
	if err != nil {
		return "", fmt.Errorf("error reading page template %s: %s", name, err)
	}
	return string(baseTmpl) + string(pageTmpl), nil
}

func expandHTMLTemplate(name string, text string, data interface{}, funcMap html_template.FuncMap) (string, error) {
	tmpl := html_template.New(name).Funcs(funcMap)
	tmpl.Option("missingkey=zero")
	tmpl.Funcs(html_template.FuncMap{
		"tmpl": func(name string, data interface{}) (html_template.HTML, error) {
			var buffer bytes.Buffer
			err := tmpl.ExecuteTemplate(&buffer, name, data)
			return html_template.HTML(buffer.String()), err
		},
	})
	tmpl, err := tmpl.Parse(text)
	if err != nil {
		return "", fmt.Errorf("error parsing template %v: %v", name, err)
	}
	var buffer bytes.Buffer
	err = tmpl.Execute(&buffer, data)
	if err != nil {
		return "", fmt.Errorf("error executing template %v: %v", name, err)
	}
	return buffer.String(), nil
}
