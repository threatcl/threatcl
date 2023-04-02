package spec

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/goccy/go-graphviz"
	dfd "github.com/marqeta/go-dfd/dfd"
	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/encoding"
)

func (d *DataFlowDiagram) GenerateDot(tmName string) (string, error) {
	tmpFile, err := ioutil.TempFile("", "dot")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpFile.Name())

	dot, err := d.generateDfdDotFile(tmpFile.Name(), tmName)
	if err != nil {
		return "", err
	}
	return dot, nil
}

func (d *DataFlowDiagram) GenerateDfdPng(filepath, tmName string) error {
	tmpFile, err := ioutil.TempFile("", "dfd")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpFile.Name())

	dot, err := d.generateDfdDotFile(filepath, tmName)
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

func (d *DataFlowDiagram) GenerateDfdSvg(filepath, tmName string) error {
	tmpFile, err := ioutil.TempFile("", "dfd")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpFile.Name())

	dot, err := d.generateDfdDotFile(filepath, tmName)
	if err != nil {
		return err
	}

	dotBytes := []byte(dot)

	err = dotToSvg(dotBytes, filepath)
	if err != nil {
		return err
	}

	return nil
}

func newDfdProcess(name string) (error, *dfd.Process) {

	newProcess := dfd.NewProcess(name)

	// @BUG: The styling below doesn't work for go-graphviz generated images
	//       but the styling will work if we output DOT and render in browser
	//       Therefore we should handle this separately depending on context
	//       I.e. if we're rendering DOT out, let's make it pretty. If not, keep
	//       it real simple. *sigh*

	// In this example, we can't set a "dashed" outline with a separate color
	// boo

	err := newProcess.SetAttribute(encoding.Attribute{
		Key:   "style",
		Value: "filled",
	})

	return err, newProcess
}

func newDfdExternalEntity(name string) (error, *dfd.ExternalService) {
	newEntity := dfd.NewExternalService(name)

	// @BUG: The styling below doesn't work for go-graphviz generated images
	//       but the styling will work if we output DOT and render in browser
	//       Therefore we should handle this separately depending on context
	//       I.e. if we're rendering DOT out, let's make it pretty. If not, keep
	//       it real simple. *sigh*

	// In this example, we set it to filled, which works in raw DOT, but not
	// in the auto generated PNG. I believe this is an issue in
	// github.com/goccy/go-graphviz

	err := newEntity.SetAttribute(encoding.Attribute{
		Key:   "style",
		Value: "filled",
	})
	return err, newEntity
}

func newDfdStore(name string) (error, *dfd.DataStore) {
	newStore := dfd.NewDataStore(name)
	err := newStore.SetAttribute(encoding.Attribute{
		Key:   "style",
		Value: "filled",
	})
	if err != nil {
		return err, nil
	}

	return err, newStore
}

// func addTrustZones(zones map[string]*dfd.TrustBoundary, processes map[string]
func addTz(parent *dfd.TrustBoundary) bool {
	fmt.Println("first")
	spew.Dump(parent)
	tb, err := parent.AddTrustBoundary("test", "red")
	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		return false
	}
	fmt.Println("second")
	spew.Dump(parent)

	parent.TrustBoundaries = make(map[string]*dfd.TrustBoundary)
	parent.TrustBoundaries["test"] = tb
	return true
}

func (d *DataFlowDiagram) generateDfdDotFile(filepath, tmName string) (string, error) {
	// Build the DFD
	g := dfd.InitializeDFD(fmt.Sprintf("%s_%s", tmName, d.Name))

	// fmt.Printf("%s\n", addTz(d))

	d.internalZones = make(map[string]*dfd.TrustBoundary)
	d.internalProcs = make(map[string]*dfd.Process)
	d.internalElems = make(map[string]*dfd.ExternalService)
	d.internalDatas = make(map[string]*dfd.DataStore)

	// Add zones
	for _, zone := range d.TrustZones {
		if _, existing := d.internalZones[zone.Name]; !existing {
			newZone, err := g.AddTrustBoundary(zone.Name, "red")
			fmt.Printf("%t\n", addTz(newZone))
			fmt.Println("Outer")
			spew.Dump(newZone)
			d.internalZones[zone.Name] = newZone
			if err != nil {
				return "", err
			}
		}

		// Add Processes from inside zone
		for _, process := range zone.Processes {
			err, newProcess := newDfdProcess(process.Name)
			if err != nil {
				return "", err
			}
			d.internalProcs[process.Name] = newProcess
			d.internalZones[zone.Name].AddNodeElem(d.internalProcs[process.Name])
		}

		// Add External Elements from inside zone
		for _, external_element := range zone.ExternalElements {
			err, newElement := newDfdExternalEntity(external_element.Name)
			if err != nil {
				return "", err
			}
			d.internalElems[external_element.Name] = newElement
			d.internalZones[zone.Name].AddNodeElem(d.internalElems[external_element.Name])
		}

		// Add Data Stores from inside zone
		for _, data_store := range zone.DataStores {
			err, newStore := newDfdStore(data_store.Name)
			if err != nil {
				return "", err
			}
			d.internalDatas[data_store.Name] = newStore
			d.internalZones[zone.Name].AddNodeElem(d.internalDatas[data_store.Name])
		}

	}

	// Add Processes
	for _, process := range d.Processes {
		err, newProcess := newDfdProcess(process.Name)
		if err != nil {
			return "", err
		}
		d.internalProcs[process.Name] = newProcess

		if process.TrustZone != "" {
			if _, ok := d.internalZones[process.TrustZone]; !ok {
				zone, err := g.AddTrustBoundary(process.TrustZone, "red")
				d.internalZones[process.TrustZone] = zone
				if err != nil {
					return "", err
				}
			}

			d.internalZones[process.TrustZone].AddNodeElem(d.internalProcs[process.Name])
		} else {
			g.AddNodeElem(d.internalProcs[process.Name])
		}
	}

	// Add External Elements
	for _, external_element := range d.ExternalElements {
		err, newElement := newDfdExternalEntity(external_element.Name)
		if err != nil {
			return "", err
		}
		d.internalElems[external_element.Name] = newElement

		if external_element.TrustZone != "" {
			if _, ok := d.internalZones[external_element.TrustZone]; !ok {
				zone, err := g.AddTrustBoundary(external_element.TrustZone, "red")
				d.internalZones[external_element.TrustZone] = zone
				if err != nil {
					return "", err
				}
			}

			d.internalZones[external_element.TrustZone].AddNodeElem(d.internalElems[external_element.Name])
		} else {
			g.AddNodeElem(d.internalElems[external_element.Name])
		}
	}

	// Add Data Stores
	for _, data_store := range d.DataStores {
		err, newStore := newDfdStore(data_store.Name)
		if err != nil {
			return "", err
		}
		d.internalDatas[data_store.Name] = newStore

		if data_store.TrustZone != "" {
			if _, ok := d.internalZones[data_store.TrustZone]; !ok {
				zone, err := g.AddTrustBoundary(data_store.TrustZone, "red")
				d.internalZones[data_store.TrustZone] = zone
				if err != nil {
					return "", err
				}
			}

			d.internalZones[data_store.TrustZone].AddNodeElem(d.internalDatas[data_store.Name])
		} else {
			g.AddNodeElem(d.internalDatas[data_store.Name])
		}
	}

	for _, flow := range d.Flows {

		var to, from graph.Node

		for name, process := range d.internalProcs {
			if name == flow.From {
				from = process
			}

			if name == flow.To {
				to = process
			}
		}

		for name, external_element := range d.internalElems {
			if name == flow.From {
				from = external_element
			}

			if name == flow.To {
				to = external_element
			}
		}

		for name, data_store := range d.internalDatas {
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

func dotToSvg(raw []byte, file string) error {
	g, err := graphviz.ParseBytes(raw)
	if err != nil {
		return err
	}
	out := graphviz.New()
	err = out.RenderFilename(g, graphviz.SVG, file)
	if err != nil {
		return err
	}
	return nil
}
