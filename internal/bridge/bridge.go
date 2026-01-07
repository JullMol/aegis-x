package bridge

import (
	"encoding/json"
	"fmt"
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

	fmt.Printf("[Bridge] Calling Python analyzer with %d ports, %d packets\n", 
		len(portsJson), len(packetsJson))

	cmd := exec.Command("python", "scripts/analyzer.py", string(portsJson), string(packetsJson))
	out, err := cmd.CombinedOutput() // Use CombinedOutput to capture stderr too
	
	if err != nil {
		fmt.Printf("[Bridge] Python error: %v\n", err)
		fmt.Printf("[Bridge] Python output: %s\n", string(out))
		return AnalysisResult{}, err
	}

	fmt.Printf("[Bridge] Python output length: %d bytes\n", len(out))

	var result AnalysisResult
	err = json.Unmarshal(out, &result)
	if err != nil {
		fmt.Printf("[Bridge] JSON unmarshal error: %v\n", err)
		fmt.Printf("[Bridge] Raw output: %s\n", string(out))
		return AnalysisResult{}, err
	}

	fmt.Printf("[Bridge] Analysis complete: %d findings, %d enriched packets\n", 
		len(result.Findings), len(result.EnrichedPackets))

	return result, nil
}