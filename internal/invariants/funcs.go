package invariants

import (
	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// allTrueFunc and anyTrueFunc mirror Terraform's alltrue/anytrue: they take a
// list of bools (for-expressions convert naturally) and quantify over it.
// alltrue([]) is true, anytrue([]) is false, and a null element counts as
// false — so `alltrue([for c in tm.controls : c.implemented])` reads the way
// a rule author expects.
var allTrueFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "list", Type: cty.List(cty.Bool)},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		for it := args[0].ElementIterator(); it.Next(); {
			_, v := it.Element()
			if v.IsNull() || v.False() {
				return cty.False, nil
			}
		}
		return cty.True, nil
	},
})

var anyTrueFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "list", Type: cty.List(cty.Bool)},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		for it := args[0].ElementIterator(); it.Next(); {
			_, v := it.Element()
			if !v.IsNull() && v.True() {
				return cty.True, nil
			}
		}
		return cty.False, nil
	},
})

// lengthFunc accepts both strings and collections, like Terraform's length
// (stdlib splits these across Strlen and Length).
var lengthFunc = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "value", Type: cty.DynamicPseudoType, AllowDynamicType: true},
	},
	Type: function.StaticReturnType(cty.Number),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		if args[0].Type() == cty.String {
			return stdlib.Strlen(args[0])
		}
		return stdlib.Length(args[0])
	},
})

// invariantFunctions is the function set available to when/condition/
// error_message expressions.
func invariantFunctions() map[string]function.Function {
	return map[string]function.Function{
		"alltrue":    allTrueFunc,
		"anytrue":    anyTrueFunc,
		"can":        tryfunc.CanFunc,
		"try":        tryfunc.TryFunc,
		"coalesce":   stdlib.CoalesceFunc,
		"compact":    stdlib.CompactFunc,
		"concat":     stdlib.ConcatFunc,
		"contains":   stdlib.ContainsFunc,
		"distinct":   stdlib.DistinctFunc,
		"element":    stdlib.ElementFunc,
		"flatten":    stdlib.FlattenFunc,
		"format":     stdlib.FormatFunc,
		"join":       stdlib.JoinFunc,
		"keys":       stdlib.KeysFunc,
		"length":     lengthFunc,
		"lookup":     stdlib.LookupFunc,
		"lower":      stdlib.LowerFunc,
		"max":        stdlib.MaxFunc,
		"merge":      stdlib.MergeFunc,
		"min":        stdlib.MinFunc,
		"regex":      stdlib.RegexFunc,
		"regexall":   stdlib.RegexAllFunc,
		"replace":    stdlib.ReplaceFunc,
		"reverse":    stdlib.ReverseListFunc,
		"sort":       stdlib.SortFunc,
		"split":      stdlib.SplitFunc,
		"substr":     stdlib.SubstrFunc,
		"trim":       stdlib.TrimFunc,
		"trimprefix": stdlib.TrimPrefixFunc,
		"trimspace":  stdlib.TrimSpaceFunc,
		"trimsuffix": stdlib.TrimSuffixFunc,
		"upper":      stdlib.UpperFunc,
		"values":     stdlib.ValuesFunc,
		"zipmap":     stdlib.ZipmapFunc,
	}
}
