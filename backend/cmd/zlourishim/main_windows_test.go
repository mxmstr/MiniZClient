package main

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestSubstituteURI(t *testing.T) {
	input := []string{`C:\Games\ZClient.exe`, "%1", "--source=%L"}
	want := []string{`C:\Games\ZClient.exe`, "zlo://one?x=1", "--source=zlo://one?x=1"}
	got, replaced := substituteURI(input, "zlo://one?x=1")
	if !replaced || !reflect.DeepEqual(got, want) {
		t.Fatalf("substituteURI() = %#v, %v; want %#v, true", got, replaced, want)
	}
}

func TestQuoteWindowsArg(t *testing.T) {
	tests := map[string]string{
		`C:\ZClient.exe`:               `C:\ZClient.exe`,
		`C:\Program Files\ZClient.exe`: `"C:\Program Files\ZClient.exe"`,
		`value"quoted`:                 `"value\"quoted"`,
		`C:\trailing slash\`:           `"C:\trailing slash\\"`,
		``:                             `""`,
	}
	for input, want := range tests {
		if got := quoteWindowsArg(input); got != want {
			t.Errorf("quoteWindowsArg(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestSplitWindowsCommandLine(t *testing.T) {
	command := `"C:\Program Files\ZClient.exe" "%1" --flag`
	want := []string{`C:\Program Files\ZClient.exe`, `%1`, `--flag`}
	got, err := splitWindowsCommandLine(command)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitWindowsCommandLine() = %#v; want %#v", got, want)
	}
}

func TestBuildBF3SingleplayerLaunchURL(t *testing.T) {
	value := buildBF3LaunchURL("SP", "")
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	command := parsed.Query().Get("cmd")
	for _, expected := range []string{"-webMode SP", "State_ResumeCampaign", `personaref=\"%ZID%\"`, `levelmode=\"sp\"`} {
		if !strings.Contains(command, expected) {
			t.Errorf("SP command %q does not contain %q", command, expected)
		}
	}
	mode, gameID := describeLaunchURL(value)
	if mode != "SP" || gameID != "" {
		t.Fatalf("describeLaunchURL() = %q, %q; want SP, empty", mode, gameID)
	}
}

func TestBuildBF3MultiplayerLaunchURL(t *testing.T) {
	value := buildBF3LaunchURL("MP", "14609")
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	command := parsed.Query().Get("cmd")
	for _, expected := range []string{"-webMode MP", "State_ClaimReservation", `gameid=\"14609\"`, `putinsquad=\"true\"`} {
		if !strings.Contains(command, expected) {
			t.Errorf("MP command %q does not contain %q", command, expected)
		}
	}
	mode, gameID := describeLaunchURL(value)
	if mode != "MP" || gameID != "14609" {
		t.Fatalf("describeLaunchURL() = %q, %q; want MP, 14609", mode, gameID)
	}
}

func TestBattlelogLaunchPattern(t *testing.T) {
	input := []byte("prefix http://localhost:5080/ZLO/run?game=Z.BF3&cmd=-webMode%20SP%20-Origin_NoAppFocus\x00suffix")
	got := string(battlelogLaunchPattern.Find(input))
	want := "http://localhost:5080/ZLO/run?game=Z.BF3&cmd=-webMode%20SP%20-Origin_NoAppFocus"
	if got != want {
		t.Fatalf("launch pattern = %q; want %q", got, want)
	}
}
