package normalizer

import "github.com/aiagentmackenzie-lang/ebm/internal/model"

// TranslateAndNormalize first translates ECS fields then normalizes to Event.
func TranslateAndNormalize(raw map[string]interface{}) model.Event {
	return Normalize(TranslateECS(raw))
}
