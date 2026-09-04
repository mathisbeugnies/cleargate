package sanitizer

import (
	"strings"
)

const CodeLineThreshold = 10

func DetectCode(input string) (bool, string) {
	lines := strings.Split(input, "\n")
	if len(lines) <= CodeLineThreshold {
		return false, ""
	}

	// Simple heuristics
	goScore := 0
	cppScore := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Go indicators
		if strings.HasPrefix(trimmed, "func ") || strings.Contains(trimmed, "fmt.") || strings.Contains(trimmed, "package ") || strings.Contains(trimmed, "err != nil") {
			goScore++
		}

		// C++ indicators
		if strings.HasPrefix(trimmed, "#include") || strings.Contains(trimmed, "std::") || strings.Contains(trimmed, "int main") || strings.Contains(trimmed, "cout <<") {
			cppScore++
		}
	}

	// Threshold for positive identification (arbitrary for demo)
	if goScore > 3 {
		return true, "Go"
	}
	if cppScore > 3 {
		return true, "C++"
	}

	return false, ""
}
