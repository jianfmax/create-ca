package create_ca

func ignoreErr[T any](t T, _ error) T {
	return t
}
