package normalizer

import "github.com/raphael/ebm/internal/model"

// TranslateAndNormalize first translates ECS fields then normalizes to Event.
func TranslateAndNormalize(raw map[string]interface{}) model.Event {
	return Normalize(TranslateECS(raw))
}
