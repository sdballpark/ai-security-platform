// Package tenant maps a gateway-issued API key to a tenant and the upstream
// provider credential that tenant's traffic should use. Clients never hold a
// real provider key; they hold a gateway key that resolves here.
package tenant

type Tenant struct {
	ID       string  // stable identifier used in rate-limit keys and audit logs
	Provider string  // which vault credential to inject for this tenant
	RateRPS  float64 // sustained requests/sec
	Burst    float64 // bucket capacity
}

type Registry struct {
	byKey map[string]Tenant
}

func NewRegistry(byKey map[string]Tenant) *Registry {
	m := make(map[string]Tenant, len(byKey))
	for k, v := range byKey {
		m[k] = v
	}
	return &Registry{byKey: m}
}

// Resolve returns the tenant for a gateway API key. The bool is false for an
// unknown key, which the gateway turns into a 401.
func (r *Registry) Resolve(apiKey string) (Tenant, bool) {
	t, ok := r.byKey[apiKey]
	return t, ok
}
