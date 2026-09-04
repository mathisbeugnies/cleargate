package sanitizer

import (
	"regexp"
	"strings"
)

type EntityType string

const (
	EntityPerson   EntityType = "PERSON"
	EntityLocation EntityType = "LOCATION"
	EntityOrg      EntityType = "ORGANIZATION"
	EntityMedical  EntityType = "MEDICAL"
)

type Entity struct {
	Type  EntityType
	Value string
	Index []int // Start, End indices
}

var (
	// Person: Mr/Ms/Dr + Name
	personHonoRegex = regexp.MustCompile(`\b(Mr|Ms|Mrs|Dr|Pr|Prof)\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b`)

	// Location: in/from/at + City/Country (Simple heuristic)
	locationRegex = regexp.MustCompile(`\b(?:in|from|at|near)\s+([A-Z][a-z]+)\b`)

	// Organization: Suffix based
	orgSuffixRegex  = regexp.MustCompile(`\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(Inc|Corp|LLC|Ltd|GmbH|Foundation|Institute)\b`)
	orgContextRegex = regexp.MustCompile(`\b(?:works|employed)\s+(?:at|by)\s+([A-Z][a-z]+)\b`)

	// Medical Dictionary
	medicalTerms = []string{
		"cancer", "diabetes", "hiv", "aids", "tumor", "diagnosis",
		"symptom", "patient", "therapy", "treatment", "prognosis",
		"syndrome", "cardiac", "stroke", "depression", "anxiety",
		"hospital", "clinic", "medication", "prescribed",
	}
)

func ScanNER(text string) []Entity {
	var entities []Entity

	// 1. Persons (Honorifics)
	matches := personHonoRegex.FindAllStringSubmatchIndex(text, -1)
	for _, m := range matches {
		// m[2], m[3] is the name group
		val := text[m[2]:m[3]]
		entities = append(entities, Entity{Type: EntityPerson, Value: val})
	}

	// 2. Organization (Suffix & Context)
	orgMatches := orgSuffixRegex.FindAllStringSubmatchIndex(text, -1)
	for _, m := range orgMatches {
		// Entire match is usually the Org name including suffix? Or group 1?
		// Regex: group 1 is Name, group 2 is Suffix. entire match is Name + Suffix.
		// Let's take entire match for Org
		val := text[m[0]:m[1]]
		entities = append(entities, Entity{Type: EntityOrg, Value: val})
	}
	orgCtxMatches := orgContextRegex.FindAllStringSubmatchIndex(text, -1)
	for _, m := range orgCtxMatches {
		val := text[m[2]:m[3]]
		entities = append(entities, Entity{Type: EntityOrg, Value: val})
	}

	// 3. Locations (Context)
	locMatches := locationRegex.FindAllStringSubmatchIndex(text, -1)
	for _, m := range locMatches {
		val := text[m[2]:m[3]] // The captured group
		// Filter out common false positives if needed (e.g. "at Monday")
		if !isCommonWord(val) {
			entities = append(entities, Entity{Type: EntityLocation, Value: val})
		}
	}

	return entities
}

func ScanMedical(text string) []string {
	var findings []string
	lower := strings.ToLower(text)
	for _, term := range medicalTerms {
		if strings.Contains(lower, term) {
			findings = append(findings, term)
		}
	}
	return findings
}

func CorrelationCheck(entities []Entity, medicalTerms []string) bool {
	hasPerson := false
	for _, e := range entities {
		if e.Type == EntityPerson {
			hasPerson = true
			break
		}
	}
	return hasPerson && len(medicalTerms) > 0
}

func isCommonWord(s string) bool {
	// Very basic filter
	common := map[string]bool{"Monday": true, "Tuesday": true, "Wednesday": true, "Thursday": true, "Friday": true, "January": true, "February": true}
	return common[s]
}
