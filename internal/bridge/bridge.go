package bridge

import (
	"encoding/json"
	"os/exec"
)

type SecurityFinding struct {
	Port    int    `json:"port"`
	Risk    string `json:"risk"`
	Summary string `json:"summary"`
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
	out, err := cmd.Output()
	if err != nil {
		return AnalysisResult{}, err
	}

	var result AnalysisResult
	err = json.Unmarshal(out, &result)
	return result, err
}