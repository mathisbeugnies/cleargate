package sanitizer

func CalculateRisk(piiCount int, secretsCount int, dlpDetected bool) int {
	score := 0

	// 10 points per PII (capped at 50)
	score += piiCount * 10

	// 30 points per Secret
	score += secretsCount * 30

	// 50 points for Code Leak
	if dlpDetected {
		score += 50
	}

	if score > 100 {
		return 100
	}
	return score
}
