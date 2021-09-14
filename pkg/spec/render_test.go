package spec

import (
	"strings"
	"testing"
)

func TestUnitToTime(t *testing.T) {
	out := unixToTime(1596964118)
	if !strings.Contains(out, "2020-08-09") {
		t.Error("Didn't convert time properly")
		t.Log(out)
	}
}

func TestTPDRender(t *testing.T) {
	cases := []struct {
		name string
		tpd  *ThirdPartyDependency
		exp  string
	}{
		{
			"empty",
			&ThirdPartyDependency{},
			"",
		},
		{
			"none",
			&ThirdPartyDependency{
				UptimeDependency: "none",
			},
			"This dependency does not represent a risk to larger product uptime.\n",
		},
		{
			"degraded",
			&ThirdPartyDependency{
				UptimeDependency: "degraded",
			},
			"This dependency could interrupt normal usage of the product and potentially contribute to larger outages.\n",
		},
		{
			"hard",
			&ThirdPartyDependency{
				UptimeDependency: "hard",
			},
			"This dependency is tightly coupled to most usage of the product and could potentially create a large or total outage.\n",
		},
		{
			"operational",
			&ThirdPartyDependency{
				UptimeDependency: "operational",
			},
			"This dependency is used for operating the product. Outages or interruptions in usage or service could contribute to a loss of introspection, an inability to triage or maintain the product, or a failure to support customers.\n",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// tpd := &ThirdPartyDependency{}

			out := tc.tpd.RenderUptime()

			if out != tc.exp {
				t.Error("RenderUptime didn't return the correct value")
				t.Log(out)
			}

		})
	}
}

func TestRenderMarkdownInvalid(t *testing.T) {
	tm := &Threatmodel{
		Name:   "test",
		Author: "x",
	}

	_, err := tm.RenderMarkdown("{{.Name")

	if err != nil && !strings.Contains(err.Error(), "Error parsing template") {
		t.Errorf("Error parsing template: %s", err)
	}

	_, err = tm.RenderMarkdown("{{nil}}")

	if err != nil && !strings.Contains(err.Error(), "Error executing template") {
		t.Errorf("Error executing template: %s", err)
	}

}

func TestRenderMarkdown(t *testing.T) {
	tm := &Threatmodel{
		Name:   "test",
		Author: "x",
	}
	tpd1 := &ThirdPartyDependency{
		Name:             "1",
		UptimeDependency: "none",
	}
	tpd2 := &ThirdPartyDependency{
		Name:             "2",
		UptimeDependency: "something",
	}
	tm.ThirdPartyDependencies = append(tm.ThirdPartyDependencies, tpd1)
	tm.ThirdPartyDependencies = append(tm.ThirdPartyDependencies, tpd2)

	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_tm",
			&Threatmodel{
				Name:   "test",
				Author: "x",
			},
			"",
			false,
		},
		{
			"valid_tm_with_uptime_dep",
			tm,
			"",
			false,
		},
		{
			"valid_tm_with_time",
			&Threatmodel{
				Name:      "test",
				Author:    "x",
				CreatedAt: 1596964118,
				UpdatedAt: 1596964118,
			},
			"",
			false,
		},
		{
			"valid_tm_with_dia",
			&Threatmodel{
				Name:        "test",
				Author:      "x",
				DiagramLink: "http://example.com/",
			},
			"",
			false,
		},
		{
			"valid_tm_with_dia_png",
			&Threatmodel{
				Name:        "test",
				Author:      "x",
				DiagramLink: "http://example.com/test.png",
			},
			"",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := tc.tm.RenderMarkdown(TmMDTemplate)

			if err != nil {
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error rendering TM: %s", tc.name, err)
				}
			} else {
				if tc.errorthrown {
					t.Errorf("%s: An error was thrown when it shouldn't have", tc.name)
				}
			}
		})
	}
}
