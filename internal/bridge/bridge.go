package bridge

import (
	"encoding/json"
	"os/exec"
)

type SecurityFinding struct {
	Port    int    `json:"port"`
	Risk    string `json:"risk"`
	Type    string `json:"type,omitempty"`
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
	Action  string `json:"action"`
}

type AnalysisResult struct {
	Findings        []SecurityFinding `json:"findings"`
	EnrichedPackets []interface{}     `json:"enriched_packets"`
}

func AnalyzeWithPython(portsData interface{}, packetsData interface{}) (AnalysisResult, error) {
	portsJson, _ := json.Marshal(portsData)
	packetsJson, _ := json.Marshal(packetsData)

	cmd := exec.Command("python", "scripts/analyzer.py", string(portsJson), string(packetsJson))
	out, err := cmd.CombinedOutput()

	if err != nil {
		return AnalysisResult{}, err
	}

	var result AnalysisResult
	err = json.Unmarshal(out, &result)
	if err != nil {
		return AnalysisResult{}, err
	}

	return result, nil
}