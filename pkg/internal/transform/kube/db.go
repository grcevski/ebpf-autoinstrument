package kube

import (
	"fmt"
	"log/slog"

	"k8s.io/client-go/tools/cache"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
)

func dblog() *slog.Logger {
	return slog.With("component", "kube.Database")
}

// Database aggregates Kubernetes information from multiple sources:
// - the informer that keep an indexed copy of the existing pods and replicasets.
// - the inspected container.Info objects, indexed either by container ID and PID namespace
// - a cache of decorated PodInfo that would avoid reconstructing them on each trace decoration
type Database struct {
	informer *kube.Metadata

	containerIDs map[string]*container.Info
	// a single namespace will point to any container inside the pod
	// but we don't care which one
	namespaces map[uint32]*container.Info

	// key: pid namespace
	fetchedPodsCache map[uint32]*kube.PodInfo

	// ip to pod name matcher
	podsByIP map[string]*kube.PodInfo
}

func StartDatabase(kubeMetadata *kube.Metadata) (*Database, error) {
	db := Database{
		fetchedPodsCache: map[uint32]*kube.PodInfo{},
		containerIDs:     map[string]*container.Info{},
		namespaces:       map[uint32]*container.Info{},
		podsByIP:         map[string]*kube.PodInfo{},
		informer:         kubeMetadata,
	}
	db.informer.AddContainerEventHandler(&db)

	if err := db.informer.AddPodEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			db.updateNewPodsByIPIndex(obj.(*kube.PodInfo))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			db.updateDeletedPodsByIPIndex(oldObj.(*kube.PodInfo))
			db.updateNewPodsByIPIndex(newObj.(*kube.PodInfo))
		},
		DeleteFunc: func(obj interface{}) {
			db.updateDeletedPodsByIPIndex(obj.(*kube.PodInfo))
		},
	}); err != nil {
		return nil, fmt.Errorf("can't register Database as Pod event handler: %w", err)
	}

	return &db, nil
}

// OnDeletion implements ContainerEventHandler
func (id *Database) OnDeletion(containerID []string) {
	for _, cid := range containerID {
		if info, ok := id.containerIDs[cid]; ok {
			delete(id.fetchedPodsCache, info.PIDNamespace)
			delete(id.namespaces, info.PIDNamespace)
		}
		delete(id.containerIDs, cid)
	}
}

// AddProcess also searches for the container.Info of the passed PID
func (id *Database) AddProcess(pid uint32) {
	ifp, err := container.InfoForPID(pid)
	if err != nil {
		dblog().Debug("failing to get container information", "pid", pid, "error", err)
		return
	}
	id.namespaces[ifp.PIDNamespace] = &ifp
	id.containerIDs[ifp.ContainerID] = &ifp
}

// OwnerPodInfo returns the information of the pod owning the passed namespace
func (id *Database) OwnerPodInfo(pidNamespace uint32) (*kube.PodInfo, bool) {
	pod, ok := id.fetchedPodsCache[pidNamespace]
	if !ok {
		info, ok := id.namespaces[pidNamespace]
		if !ok {
			return nil, false
		}
		pod, ok = id.informer.GetContainerPod(info.ContainerID)
		if !ok {
			return nil, false
		}
		id.fetchedPodsCache[pidNamespace] = pod
	}
	// we check DeploymentName after caching, as the replicasetInfo might be
	// received late by the replicaset informer
	id.informer.FetchPodOwnerInfo(pod)
	return pod, true
}

func (id *Database) updateNewPodsByIPIndex(pod *kube.PodInfo) {
	if len(pod.IPs) > 0 {
		for _, ip := range pod.IPs {
			id.podsByIP[ip] = pod
		}
	}
}

func (id *Database) updateDeletedPodsByIPIndex(pod *kube.PodInfo) {
	if len(pod.IPs) > 0 {
		for _, ip := range pod.IPs {
			delete(id.podsByIP, ip)
		}
	}
}

func (id *Database) PodInfoForIP(ip string) *kube.PodInfo {
	return id.podsByIP[ip]
}
