package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringclient "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/typed/monitoring/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"knative.dev/client/pkg/commands"
	kv1 "knative.dev/client/pkg/serving/v1"
	kn "knative.dev/serving/pkg/apis/serving/v1"
)

var ignoreList = []string{
	"dispatcher",
	"promsupp",
}

type PromSupport struct {
	namespace           string
	svcMonitorNamespace string
	interval            time.Duration
	kubeClient          *kubernetes.Clientset
	knClient            kv1.KnServingClient
	monitorClient       *monitoringclient.MonitoringV1Client
}

func (PS *PromSupport) operateService(ksvc kn.Service) error {
	serviceSpec := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            ksvc.Name + "-promservice",
			Namespace:       PS.namespace,
			OwnerReferences: ksvc.OwnerReferences,
			Labels: map[string]string{
				"app": ksvc.Name,
			},
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{
				"app": ksvc.Status.LatestReadyRevisionName,
			},
			Ports: []v1.ServicePort{
				{
					Name:     "metrics",
					Port:     8080,
					Protocol: v1.ProtocolTCP,
				},
			},
		},
	}

	svc, err := PS.kubeClient.CoreV1().Services(PS.namespace).Get(context.Background(), ksvc.Name+"-promservice", metav1.GetOptions{})

	if err != nil {
		if errors.IsNotFound(err) {
			log.Printf("Service %s not found, creating a new one", ksvc.Name+"-promservice")
			_, err := PS.kubeClient.CoreV1().Services(PS.namespace).Create(context.TODO(), serviceSpec, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("error creating service: %v", err)
			}
			log.Printf("Kubernetes Service for '%s' created successfully.\n", ksvc.Name)
		} else {
			return fmt.Errorf("error getting service: %v", err)
		}
	} else if svc.Spec.Selector["app"] != ksvc.Status.LatestReadyRevisionName {
		log.Printf("Service %s already exists, updating it", ksvc.Name+"-promservice")
		_, err := PS.kubeClient.CoreV1().Services(PS.namespace).Update(context.TODO(), serviceSpec, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("error updating service: %v", err)
		}
		log.Printf("Kubernetes Service for '%s' updated successfully.\n", ksvc.Name)
	} else {
		log.Printf("Service %s already exists and is up to date", ksvc.Name+"-promservice")
	}

	return nil
}

func (PS *PromSupport) operateServiceMonitor(ksvc kn.Service) error {
	log.Printf("Operating ServiceMonitor for service: %s", ksvc.Name)

	// Check if the ServiceMonitor already exists
	_, err := PS.monitorClient.ServiceMonitors(PS.svcMonitorNamespace).Get(context.Background(), ksvc.Name+"-servicemonitor", metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// ServiceMonitor does not exist, create it
			log.Printf("ServiceMonitor %s not found, creating it", ksvc.Name+"-servicemonitor")
			err = PS.createServiceMonitor(ksvc)
			if err != nil {
				return fmt.Errorf("error creating ServiceMonitor: %v", err)
			}
		} else {
			return fmt.Errorf("error checking for ServiceMonitor: %v", err)
		}
	} else {
		log.Printf("ServiceMonitor %s already exists", ksvc.Name+"-servicemonitor")
	}
	return nil
}

func (PS *PromSupport) createServiceMonitor(ksvc kn.Service) error {
	log.Printf("Creating Prometheus ServiceMonitor: %s-servicemonitor", ksvc.Name)

	// Define the ServiceMonitor object
	serviceMonitorSpec := &monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ksvc.Name + "-servicemonitor",
			Namespace: PS.svcMonitorNamespace,
			Labels: map[string]string{
				"app":     ksvc.Name,
				"release": "prometheus",
			},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": ksvc.Name,
				},
			},
			Endpoints: []monitoringv1.Endpoint{
				{
					Port:     "metrics",
					Interval: "10s",
				},
			},
			NamespaceSelector: monitoringv1.NamespaceSelector{
				MatchNames: []string{PS.namespace},
			},
		},
	}

	_, err := PS.monitorClient.ServiceMonitors(PS.svcMonitorNamespace).Create(context.Background(), serviceMonitorSpec, metav1.CreateOptions{})

	if err != nil {
		return fmt.Errorf("error creating service monitor: %v", err)
	}

	log.Printf("Prometheus ServiceMonitor for '%s' created successfully.\n", ksvc.Name)

	return nil
}

func (PS *PromSupport) Run() {
	ticker := time.NewTicker(PS.interval)
	defer ticker.Stop()
	for {
		<-ticker.C
		kservices, _ := PS.knClient.ListServices(context.Background())
		for _, ksvc := range kservices.Items { // iterate through all Knative services in namespace
			// Check if the service name contains any of the ignore list items
			log.Println()
			ignore := false
			for _, ignoreItem := range ignoreList {
				if strings.Contains(ksvc.Name, ignoreItem) {
					log.Printf("Ignoring ksvc: %s", ksvc.Name)
					ignore = true
					break
				}
			}
			if ignore {
				continue
			}

			log.Println("Checking knative service prom support: ", ksvc.Name)

			PS.operateService(ksvc)
			PS.operateServiceMonitor(ksvc)
		}
	}
}

func main() {
	log.Println("Starting Prometheus Support...")

	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	svcMonitorNamespace := os.Getenv("MONITORING_NAMESPACE")
	if svcMonitorNamespace == "" {
		svcMonitorNamespace = "monitoring"
	}
	interval := os.Getenv("INTERVAL")
	if interval == "" {
		interval = "10s"
	}
	intervalDuration, err := time.ParseDuration(interval)
	if err != nil {
		log.Fatalf("Invalid interval duration: %v", err)
	}

	p := commands.KnParams{}
	p.Initialize()
	// Create new knative serving client
	knClient, err := p.NewServingClient(namespace)
	if err != nil {
		log.Fatalf("Error creating Knative serving client: %s", err.Error())
	}

	config, _ := rest.InClusterConfig()
	kubeClient, _ := kubernetes.NewForConfig(config)
	monitorClient, _ := monitoringclient.NewForConfig(config)

	PS := &PromSupport{
		namespace:           namespace,
		svcMonitorNamespace: svcMonitorNamespace,
		interval:            intervalDuration,
		kubeClient:          kubeClient,
		knClient:            knClient,
		monitorClient:       monitorClient,
	}

	PS.Run()
}
