package secrets

import "regexp"

var awsKeyRe = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

// RedactAWSAccessKeys replaces live-looking AWS access key ids with a mask.
func RedactAWSAccessKeys(content string) string {
	// 2. AWS access keys
	content = awsKeyRe.ReplaceAllStringFunc(content, func(match string) string {
		return "AKIAXXXXXXXXXXXXXXXX"
	})
	return content
}
