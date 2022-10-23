package spec

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLoadSpecConfig(t *testing.T) {
	cfg, err := LoadSpecConfig()

	if err != nil {
		t.Fatalf("Error loading existing file: %s", err)
	}

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	if !cmp.Equal(cfg, defaultCfg) {
		t.Error("Populated config doesn't equal defaults")
		t.Logf("cfg: %+v\n", cfg)
		t.Logf("defaultCfg: %+v\n", defaultCfg)
	}
}

func TestLoadNonExistantSpecConfigFile(t *testing.T) {
	hcltmrcfile := "./testdata/hcltmrc-nonexistant"

	cfg, err := LoadSpecConfig()

	if err != nil {
		t.Fatalf("Error loading default spec cfg: %s", err)
	}

	err = cfg.LoadSpecConfigFile(hcltmrcfile)

	if err != nil && !strings.Contains(err.Error(), "config error: No file found") {
		t.Fatalf("Error loading a non-existent config file: %s", err)
	}

	// defaultCfg := &ThreatmodelSpecConfig{}
	// defaultCfg.setDefaults()
	//
	// if !cmp.Equal(cfg, defaultCfg) {
	// 	t.Error("Populated config doesn't equal defaults")
	// 	t.Logf("cfg: %+v\n", cfg)
	// 	t.Logf("defaultCfg: %+v\n", defaultCfg)
	// }

	// os.Remove(hcltmrcfile)
}

func TestLoadDirConfig(t *testing.T) {
	hcltmrcfile := "./testdata/"

	cfg, err := LoadSpecConfig()

	if err != nil {
		t.Fatalf("Error loading default spec cfg: %s", err)
	}

	err = cfg.LoadSpecConfigFile(hcltmrcfile)

	if err != nil && !strings.Contains(err.Error(), "We can't process directories") {
		t.Fatalf("Error loading a non-existent config file: %s", err)
	}

}

func TestLoadFullConfigFile(t *testing.T) {
	hcltmrcfile := "./testdata/full-config.hcl"

	cfg, err := LoadSpecConfig()

	if err != nil {
		t.Fatalf("Error loading default spec cfg; %s", err)
	}

	err = cfg.LoadSpecConfigFile(hcltmrcfile)

	if err != nil {
		t.Fatalf("Error loading valid cfg file: %s", err)
	}

	if cfg.DefaultInfoClassification != "1" {
		t.Errorf("Cfg file wasn't loaded correctly - DefaultInfoClassification != 1 but %s instead", cfg.DefaultInfoClassification)
	}

	if cfg.DefaultUptimeDepClassification != "N" {
		t.Errorf("Cfg file wasn't loaded correctly - DefaultUptimeDepClassification != N but %s instead", cfg.DefaultUptimeDepClassification)
	}

	if !reflect.DeepEqual(cfg.InitiativeSizes, []string{"S", "M", "L"}) {
		t.Errorf("Cfg file wasn't loaded correctly - InitiativeSizes != ['S', 'M', 'L'] but %s instead", cfg.InitiativeSizes)
	}

}

func TestLoadPartialConfigFile(t *testing.T) {
	hcltmrcfile := "./testdata/partial-config.hcl"

	cfg, err := LoadSpecConfig()

	if err != nil {
		t.Fatalf("Error loading default spec cfg; %s", err)
	}

	err = cfg.LoadSpecConfigFile(hcltmrcfile)

	if err != nil {
		t.Fatalf("Error loading valid cfg file: %s", err)
	}

	if cfg.DefaultInfoClassification != "Confidential" {
		t.Errorf("Cfg file wasn't loaded correctly - DefaultInfoClassification != Confidential but %s instead", cfg.DefaultInfoClassification)
	}

	if cfg.DefaultUptimeDepClassification != "none" {
		t.Errorf("Cfg file wasn't loaded correctly - DefaultUptimeDepClassification != none but %s instead", cfg.DefaultUptimeDepClassification)
	}

	if !reflect.DeepEqual(cfg.ImpactTypes, []string{"big", "small"}) {
		t.Errorf("Cfg file wasn't loaded correctly - ImpactTypes != ['big', 'small'] but %s instead", cfg.ImpactTypes)
	}

}

func TestLoadInvalidFiles(t *testing.T) {
	cases := []struct {
		name string
		file string
		exp  string
	}{
		{
			"missing_quote",
			"./testdata/hcltmrc-invalid-multi",
			"Invalid multi-line string",
		},
		{
			"invalid_block",
			"./testdata/hcltmrc-invalid-block",
			"Invalid block definition",
		},
		{
			"sompida",
			"./testdata/hcltmrc",
			"An argument named \"config_version\" is not expected here",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := LoadSpecConfig()

			if err != nil {
				t.Fatalf("Error loading default spec cfg: %s", err)
			}

			err = cfg.LoadSpecConfigFile(tc.file)

			if err != nil && !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("Error loading invalid cfg file: %s", err)
			}
		})
	}
}
