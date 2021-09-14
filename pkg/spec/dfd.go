package spec

import (
	"io/ioutil"
	"os"

	"github.com/goccy/go-graphviz"
	dfd "github.com/marqeta/go-dfd/dfd"
	"gonum.org/v1/gonum/graph"
)

func (tm *Threatmodel) GenerateDfdPng(filepath string) error {
	tmpFile, err := ioutil.TempFile("", "dfd")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpFile.Name())

	dot, err := tm.generateDfdDotFile(tmpFile.Name())
	if err != nil {
		return err
	}

	dotBytes := []byte(dot)

	err = dotToPng(dotBytes, filepath)
	if err != nil {
		return err
	}

	return nil
}

func (tm *Threatmodel) generateDfdDotFile(filepath string) (string, error) {
	// Build the DFD
	g := dfd.InitializeDFD(tm.Name)

	zones := make(map[string]*dfd.TrustBoundary)

	// Add Processes
	processes := make(map[string]*dfd.Process)
	for _, process := range tm.DataFlowDiagram.Processes {
		processes[process.Name] = dfd.NewProcess(process.Name)

		if process.TrustZone != "" {
			if _, ok := zones[process.TrustZone]; !ok {
				zone, err := g.AddTrustBoundary(process.TrustZone)
				zones[process.TrustZone] = zone
				if err != nil {
					return "", err
				}
			}

			zones[process.TrustZone].AddNodeElem(processes[process.Name])
		} else {
			g.AddNodeElem(processes[process.Name])
		}
	}

	// Add External Elements
	external_elements := make(map[string]*dfd.ExternalService)
	for _, external_element := range tm.DataFlowDiagram.ExternalElements {
		external_elements[external_element.Name] = dfd.NewExternalService(external_element.Name)

		if external_element.TrustZone != "" {
			if _, ok := zones[external_element.TrustZone]; !ok {
				zone, err := g.AddTrustBoundary(external_element.TrustZone)
				zones[external_element.TrustZone] = zone
				if err != nil {
					return "", err
				}
			}

			zones[external_element.TrustZone].AddNodeElem(external_elements[external_element.Name])
		} else {
			g.AddNodeElem(external_elements[external_element.Name])
		}
	}

	// Add Data Stores
	data_stores := make(map[string]*dfd.DataStore)
	for _, data_store := range tm.DataFlowDiagram.DataStores {
		data_stores[data_store.Name] = dfd.NewDataStore(data_store.Name)

		if data_store.TrustZone != "" {
			if _, ok := zones[data_store.TrustZone]; !ok {
				zone, err := g.AddTrustBoundary(data_store.TrustZone)
				zones[data_store.TrustZone] = zone
				if err != nil {
					return "", err
				}
			}

			zones[data_store.TrustZone].AddNodeElem(data_stores[data_store.Name])
		} else {
			g.AddNodeElem(data_stores[data_store.Name])
		}
	}

	for _, flow := range tm.DataFlowDiagram.Flows {

		var to, from graph.Node

		for name, process := range processes {
			if name == flow.From {
				from = process
			}

			if name == flow.To {
				to = process
			}
		}

		for name, external_element := range external_elements {
			if name == flow.From {
				from = external_element
			}

			if name == flow.To {
				to = external_element
			}
		}

		for name, data_store := range data_stores {
			if name == flow.From {
				from = data_store
			}

			if name == flow.To {
				to = data_store
			}
		}

		// g.AddFlow(processes[flow.From], processes[flow.To], flow.Name)
		g.AddFlow(from, to, flow.Name)
	}

	// Construct temp file for the dot file output
	// The library we use needs to save an actual file,
	// even though we don't use it, and instead use the raw
	// text output
	client := dfd.NewClient(filepath)
	dot, err := client.DFDToDOT(g)
	if err != nil {
		return "", err
	}
	return dot, nil
}

func dotToPng(raw []byte, file string) error {
	g, err := graphviz.ParseBytes(raw)
	if err != nil {
		return err
	}

	out := graphviz.New()
	err = out.RenderFilename(g, graphviz.PNG, file)
	if err != nil {
		return err
	}
	return nil
}
