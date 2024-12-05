package utils

import (
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/microsoft/retina/pkg/log"
)

func TestToFlowTrafficDirection(t *testing.T) {
	tests := []struct {
		input    uint8
		expected flow.TrafficDirection
	}{
		{0, flow.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN},
		{1, flow.TrafficDirection_INGRESS},
		{2, flow.TrafficDirection_EGRESS},
		{3, flow.TrafficDirection_TRAFFIC_DIRECTION_UNKNOWN},
	}

	for _, test := range tests {
		result := toFlowTrafficDirection(test.input)
		if result != test.expected {
			t.Errorf("toFlowTrafficDirection(%d) = %v; want %v", test.input, result, test.expected)
		}
	}
}

func TestToConntrackFLow(t *testing.T) {
	// Mock data for ConntrackMetricsMetadata
	ctm := &ConntrackMetricsMetadata{
		Timestamp:        time.Now().Unix(),
		SrcIP:            "192.168.1.1",
		DstIP:            "192.168.1.2",
		Proto:            6, // TCP
		SrcPort:          12345,
		DstPort:          80,
		TrafficDirection: 1,
		Metrics: &ConntrackMetricsMetadataValues{
			PacketsCount: 100,
			BytesCount:   2048,
		},
		Logger: &log.ZapLogger{}, // No-op logger for testing
	}

	f := ToConntrackFLow(ctm)

	if f.Type != flow.FlowType_L3_L4 {
		t.Errorf("Expected flow type %v, got %v", flow.FlowType_L3_L4, f.Type)
	}
	if f.IP.Source != ctm.SrcIP {
		t.Errorf("Expected source IP %v, got %v", ctm.SrcIP, f.IP.Source)
	}
	if f.IP.Destination != ctm.DstIP {
		t.Errorf("Expected destination IP %v, got %v", ctm.DstIP, f.IP.Destination)
	}
	if f.IP.IpVersion != flow.IPVersion_IPv4 {
		t.Errorf("Expected IP version %v, got %v", flow.IPVersion_IPv4, f.IP.IpVersion)
	}
	if f.Verdict != flow.Verdict_FORWARDED {
		t.Errorf("Expected verdict %v, got %v", flow.Verdict_FORWARDED, f.Verdict)
	}
	if f.TrafficDirection != flow.TrafficDirection_INGRESS {
		t.Errorf("Expected traffic direction %v, got %v", flow.TrafficDirection_INGRESS, f.TrafficDirection)
	}
	expectedSummary := "[Conntrack] Packets: 100, Bytes: 2048"
	if f.Summary != expectedSummary {
		t.Errorf("Expected summary %v, got %v", expectedSummary, f.Summary)
	}
}
