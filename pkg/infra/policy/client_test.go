package policy_test

import (
	"testing"

	"github.com/m-mizutani/gt"
	"github.com/m-mizutani/vulnivore/pkg/domain/model"
	"github.com/m-mizutani/vulnivore/pkg/infra/policy"
)

func TestPolicyP1(t *testing.T) {
	type input struct {
		Color string `json:"color"`
	}
	type output struct {
		V1 int `json:"v1"`
	}

	in1 := input{Color: "red"}
	in2 := input{Color: "blue"}
	var o1, o2 output
	p := gt.R1(policy.New(policy.WithDir("testdata"))).NoError(t)
	gt.NoError(t, p.Query(model.NewContext(), "p1", &in1, &o1))
	gt.NoError(t, p.Query(model.NewContext(), "p1", &in2, &o2))

	gt.Equal(t, o1.V1, 6)
	gt.Equal(t, o2.V1, 5)
}

func TestPolicyP2(t *testing.T) {
	type input struct {
		Color string `json:"color"`
	}
	type output struct {
		V2 []int `json:"v2"`
	}

	in1 := input{Color: "red"}
	in2 := input{Color: "blue"}
	var o1, o2 output
	p := gt.R1(policy.New(policy.WithDir("testdata"))).NoError(t)
	gt.NoError(t, p.Query(model.NewContext(), "p2", &in1, &o1))
	gt.NoError(t, p.Query(model.NewContext(), "p2", &in2, &o2))

	gt.A(t, o1.V2).Length(0)
	gt.A(t, o2.V2).Length(2).Have(2).Have(3)
}

func TestPrintHook(t *testing.T) {
	var called int
	type output struct {
		Res string `json:"res"`
	}

	p := gt.R1(policy.New(
		policy.WithDir("testdata"),
		policy.WithPrinter(func(ctx *model.Context, file string, row int, msg string) error {
			called++
			gt.Equal(t, file, "testdata/d4/policy.rego")
			gt.Equal(t, row, 4)
			gt.Equal(t, msg, "hello, blue")
			t.Log(file, row, msg)
			return nil
		}),
	)).NoError(t)

	var out output
	gt.NoError(t, p.Query(model.NewContext(), "p3", nil, &out))
	gt.Equal(t, called, 1)
	gt.Equal(t, out.Res, "ok")
}
