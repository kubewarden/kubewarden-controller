package utils

func IsStringInSlice(element string, elements []string) bool {
	for _, current := range elements {
		if current == element {
			return true
		}
	}
	return false
}

func AddStringToSliceIfNotExists(element string, elements []string) []string {
	res := []string{}
	for _, current := range elements {
		if IsStringInSlice(current, elements) {
			continue
		}
		res = append(res, current)
	}
	res = append(res, element)
	return res
}

func RemoveStringFromSlice(element string, elements []string) []string {
	res := []string{}
	for _, current := range elements {
		if current != element {
			res = append(res, current)
		}
	}
	return res
}
