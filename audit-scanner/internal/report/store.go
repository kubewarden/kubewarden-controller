package report

import (
	"encoding/json"
	"errors"
	"sync"
)

// PolicyReportStore caches the latest version of PolicyReports
type policyReportStore struct {
	// store is a map of namespaces and namespaced PolicyReports
	store map[string]RInterface
	// clusterPR is the sole ClusterPolicyReport
	clusterPR ClusterPolicyReport

	rwm *sync.RWMutex
}

type PolicyReportStore interface {
	// Add a PolicyReport to the Store
	Add(r RInterface) error
	// Get PolicyReport by namespace
	Get(ns string) (RInterface, error)
	// Get the ClusterPolicyReport
	GetClusterWide() (RInterface, error)
	// Update ClusterPolicyReport or PolicyReport. ns argument is used in case
	// of namespaced PolicyReport
	Update(r RInterface) error
	// Delete PolicyReport by namespace
	Remove(ns string) error
	// Delete all namespaced PolicyReports
	RemoveAllNamespaced() error
	// Marshal the contents of the store into a JSON string
	ToJSON() (string, error)
}

// NewPolicyReportStore construct a PolicyReportStore, initializing the
// clusterwide ClusterPolicyReport
func NewPolicyReportStore() PolicyReportStore {
	return &policyReportStore{
		store:     make(map[string]RInterface),
		clusterPR: *NewCPR("clusterwide"),
		rwm:       new(sync.RWMutex),
	}
}

func (s *policyReportStore) Add(report RInterface) error {
	s.rwm.Lock()
	defer s.rwm.Unlock()
	if report.GetType() == ClusterPolicyReportType {
		cpr, _ := report.(*ClusterPolicyReport)
		s.clusterPR = *cpr
	} else {
		s.store[report.GetNamespace()] = report
	}
	return nil
}

func (s *policyReportStore) Get(namespace string) (RInterface, error) {
	s.rwm.RLock()
	report, present := s.store[namespace]
	s.rwm.RUnlock()
	if present {
		return report, nil
	}
	return nil, errors.New("report not found")
}

func (s *policyReportStore) GetClusterWide() (RInterface, error) {
	s.rwm.RLock()
	report := s.clusterPR
	s.rwm.RUnlock()
	return RInterface(&report), nil
}

func (s *policyReportStore) Update(report RInterface) error {
	s.rwm.Lock()
	defer s.rwm.Unlock()
	if report.GetType() == ClusterPolicyReportType {
		cpr, _ := report.(*ClusterPolicyReport)
		s.clusterPR = *cpr
	} else {
		s.store[report.GetNamespace()] = report
	}
	return nil
}

func (s *policyReportStore) Remove(namespace string) error {
	if _, err := s.Get(namespace); err == nil {
		s.rwm.Lock()
		defer s.rwm.Unlock()
		delete(s.store, namespace)
	}
	return nil
}

func (s *policyReportStore) RemoveAllNamespaced() error {
	s.rwm.Lock()
	defer s.rwm.Unlock()
	s.store = make(map[string]RInterface)
	return nil
}

func (s *policyReportStore) ToJSON() (string, error) {
	var str string

	marshaled, err := json.Marshal(s.clusterPR)
	if err != nil {
		return "", err
	}
	str = (string(marshaled))
	for _, report := range s.store {
		marshaled, err := json.Marshal(report)
		if err != nil {
			return "", err
		}

		str += (string(marshaled))
	}
	return str, nil
}
