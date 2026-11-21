package telegram

import (
	"reflect"
	"testing"
)

func TestExtract(t *testing.T) {
	cases := []struct {
		name string
		text string
		ents []Entity
		want []Item
	}{
		{
			name: "entity offsets in UTF-16 after emoji",
			text: "🎁🎁 Klaim: bca-hadiah.xyz/klaim",
			ents: []Entity{{Type: "url", Offset: 12, Length: 20}},
			want: []Item{{Kind: ItemLink, Value: "bca-hadiah.xyz/klaim"}},
		},
		{
			name: "hidden text link",
			text: "Klik di sini",
			ents: []Entity{{Type: "text_link", Offset: 0, Length: 12, URL: "http://phish.top/a"}},
			want: []Item{{Kind: ItemLink, Value: "http://phish.top/a"}},
		},
		{
			name: "plain url and trailing punctuation",
			text: "buka https://jnt-resi.xyz/apk.",
			want: []Item{{Kind: ItemLink, Value: "https://jnt-resi.xyz/apk"}},
		},
		{
			name: "phone formats",
			text: "WA 0812-3456-7890 atau +62 813 1111 2222, kode 123456",
			want: []Item{{Kind: ItemPhone, Value: "0812-3456-7890"}, {Kind: ItemPhone, Value: "+62 813 1111 2222"}},
		},
		{
			name: "bank account with label",
			text: "Transfer ke BCA no rek: 123-456-7890 a.n. Budi",
			want: []Item{{Kind: ItemAccount, Provider: "bca", Value: "123-456-7890"}},
		},
		{
			name: "alias and e-wallet; 'dana' as a word is ignored",
			text: "Jenius 90012345678, DANA 081299998888, dana 500000 cair",
			want: []Item{
				{Kind: ItemAccount, Provider: "btpn", Value: "90012345678"},
				{Kind: ItemAccount, Provider: "dana", Value: "081299998888"},
				{Kind: ItemPhone, Value: "081299998888"},
			},
		},
		{
			name: "duplicates",
			text: "081234567890 / +6281234567890 / http://a.xyz http://a.xyz",
			want: []Item{{Kind: ItemLink, Value: "http://a.xyz"}, {Kind: ItemPhone, Value: "081234567890"}},
		},
		{
			name: "nothing",
			text: "Halo, apa kabar? Nomor antrian 12345.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Extract(c.text, c.ents)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Extract = %#v\ningin %#v", got, c.want)
			}
		})
	}
}

func TestExtractCap(t *testing.T) {
	text := "http://a1.xyz http://a2.xyz http://a3.xyz http://a4.xyz http://a5.xyz http://a6.xyz"
	if got := Extract(text, nil); len(got) != MaxItems {
		t.Fatalf("jumlah item = %d", len(got))
	}
}
