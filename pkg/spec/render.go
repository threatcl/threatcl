package spec

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// Interface Renderer defines datastructures that can output markdown
// representations of themselves.
// type Renderer interface {
// 	Render() (string, error)
// }

func (tm *Threatmodel) RenderMarkdown(mdTemplate string) (io.Reader, error) { // not super sure about this function signature
	mdBuffer := new(bytes.Buffer)

	tmpl, err := ParseTMTemplate(mdTemplate)
	if err != nil {
		return mdBuffer, fmt.Errorf("Error parsing template: %w", err)
	}

	err = tmpl.Execute(mdBuffer, tm)
	if err != nil {
		return mdBuffer, fmt.Errorf("Error executing template: %w", err)
	}
	return mdBuffer, nil
}

func ParseTMTemplate(mdTemplate string) (*template.Template, error) {
	return template.New("TMTemplate").Funcs(template.FuncMap{
		"isImage": func(url string) bool {
			imageExts := map[string]interface{}{
				".jpg":  nil,
				".png":  nil,
				"*.svg": nil,
			}

			ext := strings.ToLower(filepath.Ext(url))

			if _, ok := imageExts[ext]; ok {
				return true
			}
			return false
		},
		"unixToTime": unixToTime,
		"ToUpper": func(input interface{}) string { // yikes
			switch val := input.(type) {
			case string:
				return strings.ToUpper(val)
			case UptimeDependencyClassification:
				return strings.ToUpper(string(val))
			default:
				return ""
			}
		},
	}).Parse(mdTemplate)
}

func unixToTime(unixtime int64) string {
	utime := time.Unix(unixtime, 0)
	return utime.Format("2006-01-02")
}

func (dep *ThirdPartyDependency) RenderUptime() string {
	if dep.UptimeDependency == "" {
		return ""
	}

	var sb strings.Builder
	// sb.WriteString(fmt.Sprintf("This dependency has an uptime classification of %s, which means ", strings.ToUpper(string(dep.UptimeDependency))))
	if dep.UptimeDependency == NoneUptime {
		sb.WriteString("This dependency does not represent a risk to larger product uptime.\n")
	}
	if dep.UptimeDependency == DegradedUptime {
		sb.WriteString("This dependency could interrupt normal usage of the product and potentially contribute to larger outages.\n")
	}
	if dep.UptimeDependency == HardUptime {
		sb.WriteString("This dependency is tightly coupled to most usage of the product and could potentially create a large or total outage.\n")
	}
	if dep.UptimeDependency == OperationalUptime {
		sb.WriteString("This dependency is used for operating the product. Outages or interruptions in usage or service could contribute to a loss of introspection, an inability to triage or maintain the product, or a failure to support customers.\n")
	}

	sb.WriteString(dep.UptimeNotes)

	return sb.String()
}
