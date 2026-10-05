package mcptools

import (
	"context"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
	"github.com/emersion/go-vcard"
)

func (f *fakeProton) addContact(t *testing.T, name string, emails ...string) {
	t.Helper()
	card, err := gpa.NewCard(nil, gpa.CardTypeClear)
	if err != nil {
		t.Fatal(err)
	}
	if err := card.Set(nil, vcard.FieldFormattedName, &vcard.Field{Value: name}); err != nil {
		t.Fatal(err)
	}
	for _, e := range emails {
		if err := card.Add(nil, vcard.FieldEmail, &vcard.Field{Value: e}); err != nil {
			t.Fatal(err)
		}
	}
	if err := card.Set(nil, vcard.FieldTelephone, &vcard.Field{Value: "+41 79 000 00 00"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sess.Client.CreateContacts(context.Background(), gpa.CreateContactsReq{
		Contacts: []gpa.ContactCards{{Cards: gpa.Cards{card}}},
	}); err != nil {
		t.Fatalf("create contact: %v", err)
	}
}

func TestContactsSearch(t *testing.T) {
	f := newFakeProton(t)
	f.addContact(t, "Hans Muster", "hans@juliusbaer.com", "h.muster@private.ch")
	f.addContact(t, "Anna Advokat", "anna@lawfirm.ch")
	f.addContact(t, "Board Secretary", "secretary@company.example")
	tl := contactsSearch(f.deps())

	type out struct {
		Contacts []struct {
			Name   string   `json:"name"`
			Emails []string `json:"emails"`
		} `json:"contacts"`
		Total int `json:"total"`
	}
	var r out
	res := callTool(t, tl, `{"query":"juliusbaer"}`, &r)
	if strings.Contains(res.Content[0].Text, "+41") {
		t.Error("phone number leaked into the result")
	}
	if r.Total != 1 || r.Contacts[0].Name != "Hans Muster" || len(r.Contacts[0].Emails) != 2 {
		t.Errorf("by email: %+v", r)
	}

	r = out{}
	callTool(t, tl, `{"query":"ADVOKAT"}`, &r)
	if r.Total != 1 || r.Contacts[0].Emails[0] != "anna@lawfirm.ch" {
		t.Errorf("by name, case-insensitive: %+v", r)
	}

	r = out{}
	callTool(t, tl, `{"query":"","limit":2}`, &r)
	if r.Total != 3 || len(r.Contacts) != 2 || r.Contacts[0].Name != "Anna Advokat" {
		t.Errorf("list with limit: %+v", r)
	}

	r = out{}
	callTool(t, tl, `{"query":"nobody"}`, &r)
	if r.Total != 0 || r.Contacts == nil {
		t.Errorf("no match should be an empty array: %+v", r)
	}
}
