package tunnel

import (
	"testing"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input     string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{"8080", 8080, 8080, false},
		{" 443 ", 443, 443, false},
		{"9000-9005", 9000, 9005, false},
		{" 1000 - 1005 ", 1000, 1005, false},
		{"", 0, 0, true},
		{"0", 0, 0, true},
		{"70000", 0, 0, true},
		{"9010-9000", 0, 0, true},
		{"abc", 0, 0, true},
		{"80-abc", 0, 0, true},
		{"80-85-90", 0, 0, true},
	}

	for _, tt := range tests {
		start, end, err := ParsePortRange(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePortRange(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if start != tt.wantStart || end != tt.wantEnd {
				t.Errorf("ParsePortRange(%q) = (%d, %d), want (%d, %d)",
					tt.input, start, end, tt.wantStart, tt.wantEnd)
			}
		}
	}
}

func TestExpandPortRange(t *testing.T) {
	tests := []struct {
		local   string
		remote  string
		want    []PortPair
		wantErr bool
	}{
		{"8080", "8080", []PortPair{{8080, 8080}}, false},
		{"9000-9002", "8000-8002", []PortPair{
			{9000, 8000},
			{9001, 8001},
			{9002, 8002},
		}, false},
		{"9000-9005", "8000-8002", nil, true}, // count mismatch (6 vs 3)
		{"invalid", "8080", nil, true},
		{"8080", "invalid", nil, true},
	}

	for _, tt := range tests {
		got, err := ExpandPortRange(tt.local, tt.remote)
		if (err != nil) != tt.wantErr {
			t.Errorf("ExpandPortRange(%q, %q) error = %v, wantErr %v", tt.local, tt.remote, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if len(got) != len(tt.want) {
				t.Errorf("ExpandPortRange(%q, %q) len = %d, want %d", tt.local, tt.remote, len(got), len(tt.want))
				continue
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ExpandPortRange(%q, %q)[%d] = %+v, want %+v", tt.local, tt.remote, i, got[i], tt.want[i])
				}
			}
		}
	}
}

func TestParsePortMappingSpec(t *testing.T) {
	tests := []struct {
		spec    string
		wantLen int
		wantErr bool
	}{
		{"8080:8080", 1, false},
		{"9000-9005:8000-8005", 6, false},
		{"9000-9005:8000", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		pairs, err := ParsePortMappingSpec(tt.spec)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePortMappingSpec(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && len(pairs) != tt.wantLen {
			t.Errorf("ParsePortMappingSpec(%q) len = %d, want %d", tt.spec, len(pairs), tt.wantLen)
		}
	}
}
