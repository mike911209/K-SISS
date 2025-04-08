# SSIS: Scalable Serving Inference System

## About

## Prerequisites
* A k8s cluster with version > 1.28
* Nodes with MIG or MPS capable GPUs

## Getting Start

### 1. Setup MIG Resources to k8s Cluster

#### Clean Up Exist Environment

1. In Master node, delete existing device plugin if exist 
2. Login Worker Node
3. Run `sudo systemctl stop nvidia-persistenced` to stop all persistent process running on the node
4. Run `sudo systemctl stop nvidia-dcgm` to stop dcgm processes
5. Use `sudo lsof /dev/nvidia* ` to check if this command has empty output

#### Partition MIG slice
1. Login to worker node
2. You can partition GPU slices through the command：
```
sudo nvidia-smi mig -i 0 -cgi <slice 1>,<slice 2>,...  -C
```
* Valid Slice type are listed below: 
```
| Slice   | SM     | Memory | Cache | Max Count |
|---------|--------|--------|-------|-----------|
| 7g.40gb | 7 GPC  | 40 GB  | Full  | 1         |
| 4g.20gb | 4 GPC  | 20 GB  | 4/8   | 1         |
| 3g.20gb | 3 GPC  | 20 GB  | 4/8   | 2         |
| 2g.10gb | 2 GPC  | 10 GB  | 2/8   | 3         |
| 1g.5gb  | 1 GPC  | 5 GB   | 1/8   | 7         |
```

* You can find the valid GPU slice combinations in [here](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/#a100-mig-profiles)


#### Set Up MIG device plugin

* Install NVIDIA gpu-operator device plugin:
```
helm install --wait --generate-name \
-n gpu-operator --create-namespace \
nvidia/gpu-operator \
--set mig.strategy=mixed \
--set migManager.config.name=custom-mig-parted-config
```

#### Check MIG setup
* Run `kubectl describe node` and check if the mig resources are set and allocatable
* ex : 
```
Capacity:
  ...
  nvidia.com/1g.5gb:       1
  nvidia.com/2g.10gb:      0
  ...

Allocatable:
  ...
  nvidia.com/1g.5gb:       1
  nvidia.com/2g.10gb:      0
  ...

```

### 2. Setup SSIS-Dispatcher 

#### About
The SSIS-Dispatcher project is a subproject branched from the SSIS(Scalable Serving Inference System for Language Models with NVIDIA MIG) project. It is a served as a serving manager component in the system. SSIS-Dispatcher is capable of receiving model inference requests and luanching inference pod under [Knative](https://knative.dev/docs/) framework while leveraging GPU sharing features supported my Nvidia [Multi-Instance GPU(MIG)](https://www.nvidia.com/en-us/technologies/multi-instance-gpu/) or [Multi-Process Service (MPS)](https://docs.nvidia.com/deploy/mps/index.html), which allows finegrained unitlization of GPU resources, enhancing system efficiency.
* Check out the [SSIS project repo](https://github.com/mike911209/KubeComp-MIG), for additional autoscaler or performance monitor support.

#### Prerequisite
* Fill three placeholder in `configuration.yaml`, `makefile`, and `config.go`. (Global search "PLACEHOLDER" to find all placeholders)
* This demo project runs all knative service, pods  on `nthulab` namespace
* You should have MIG or MPS kubernetes resource registered on your cluster
* The MIG resource defined in node should be the resource name format below:
```
nvidia.com/mig-1g.5gb
nvidia.com/mig-2g.10gb
nvidia.com/mig-3g.20gb
nvidia.com/mig-4g.20gb
nvidia.com/mig-7g.40gb
```
* The MPS resource defined in node should be the resource name format below:
```
nvidia.com/gpu-1gb
nvidia.com/gpu-2gb
nvidia.com/gpu-3gb
nvidia.com/gpu-4gb
...
nvidia.com/gpu-30gb
nvidia.com/gpu-31gb
nvidia.com/gpu-32gb
```

#### 1. Setup Knative and Kourier Ingress/ Load Balancer

* Run `make setup_knative`
* `k get po -n kourier-system`, check if kourier gateway is running
* `k get svc -n kourier-system`, check if kourier svc and kourier-internal service is established
* You can use `curl <kourier service external ip>` to test kourier external gateway or run a pod on cluster that runs `curl http://kourier-internal.kourier-system.svc.cluster.local` to check the in-cluster gateway is operating
* Use `kn service list` and find the url for the dispatcher, ex: `http://dispatcher.nthulab.192.168.1.10.sslip.io`

#### 2. Build Your Own Dispatcher Image

* Run `make build`

#### 3. Deploy dispatcher

* Run `make deploy`

#### 4. Forward kourier in-cluster gateway 

* Assume the cluster external ip is unavailable, we make our test using in-cluster ip, which is likely available in most cases

* Open another terminal window , then : `make forward`

#### 5. Send test API request to Dispatcher
* Export your HuggingFace token : `export HF_TOKEN="<Your token>"`
* Run `make test`, to send sample inference request 
* (OPTIONAL): if your cluster support external ip , you can try send your request through external ip using this command template:
```
# Assume kourier service external ip is 192.168.1.10
curl -X POST http://192.168.1.10:80 \
		-H "Host: dispatcher.nthulab.192.168.1.10.sslip.io" \
		-H "Content-Type: application/json" \
		-d '{"token":"What is Deep Learning?","par":{"max_new_tokens":20},"env": {"MODEL_ID":"openai-community/gpt2","HF_TOKEN":"$(HF_TOKEN)"}}'
```
#### Uninstalling Dispatcher 
* Delete all service running
* Run `make clean` to remove dispatcher
* Run `make remove_knative` to remove knative

### 2. Setup Autoascaler and Prometheus 

#### About

K-SISS Autoscaler is an GPU-aware autoscaler for inference workloads (e.g., LLMs) deployed in Knative and Kubernetes.  
It adjusts GPU resource tiers (MIG, MPS, or full GPU) dynamically based on application metrics like latency and throughput.

#### Features

- **Dynamic GPU Tier Scaling** — supports MIG, MPS, and full GPU
- **Metric-Based Decisions** — driven by Prometheus metrics (e.g., latency, tokens/sec)
- **Knative + Prometheus Integration** — integrated with Knatie and Prometheus

#### Build & Run
> Make sure to configure the `makefile` for your Docker or GitHub container registry.

Build your image:
```
make build
```

Edit configuration.yaml to match your environment (e.g., namespace, metric queries).

Deploy into you k8s cluster:
```
make deploy
```
>  This will use configuration.yaml to deploy the autoscaler

#### Project Structure
```
Autoscaler/
├── autoscaler.go
├── configuration.yaml
├── Dockerfile
├── exporter.go
├── go.mod
├── go.sum
├── gpuRegistry.go
├── gpuResource.go
├── knativeHelper.go
├── makefile
├── metricsFetcher.go
├── README.md
└── scaler.go
``` 

#### autoscaler.go
Top-level module that processes each inference service and initializes all submodules.

#### exporter.go
Promehteus metrics exporter, enabling visualization of scaling activity.

Exposes the following metrics:
- Gpu resource currently used by inference services
- Inference performance metrics obtain from Prometheus

#### gpuRegistry.go
GPU resource manager, Maintains available GPU tiers and provides tier resolution logic.

Handles:
- Cluster GPU tier initialization
- Validating scaling actions based on available tiers

#### gpuResource.go
Defines the `gpuResource` struct, which encapsulates all metadata about a GPU resource (type, tier, CPU/memory size).

#### knativeHelper.go
Utility functions to interact with Knative Services and Revisions.

#### metricsFetcher.go
Fetches Prometheus metrics based on queries defined in `configuration.yaml`.
- Reading metric configurations from the ConfigMap
- Querying metrics per pod to inform scaling logic

#### scaler.go
Contains the scaling policy and decision logic.
- Determines whether to scale up, down, in, or out
- Does not track GPU availability — it only decides what should happen
- Executes scaling by:
    - Creating new inference pods with upgraded resources
    - Updating Knative traffic routing
    - Deleting old revisions (in case of up/down/in scaling)

#### configuration.yaml
Defines all Kubernetes resources needed to run the autoscaler. Edit this file to configure namespaces, metric queries.

#### Customization
#### Add new metrics for scaling decision
To add new metrics for scaling decisions, modify the autoscaler-config ConfigMap (defined in `configuration.yaml`):

For example, say you want to create metrics for app llama3:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: autoscaler-config
  namespace: default
  labels:
    app: autoscaler
data:
  llama3: |
    - name: <define your metric name>
      query: <write your promQL query here>
      slo: <slo to scale inference server>
      scaleDownFactor:
      scaleUpFactor:
```
> Each section under a key like llama3 corresponds to one inference service.

#### Custom scaling policy
To change how scaling decisions are made, modify the `DecideScale` function in `scaler.go`.

> The current implementation only considers a single metric when deciding to scale up or down. You can extend it to support multi-metric logic or weighted scoring.

#### Register new gpu resources
Extend gpuRegistry.go to define new GPU tiers, such as:
- MIG configuration
- MPS virtual slices


### 3. Send Request to SSIS

#### Send Customize request to Dispatcher
* Make sure you done all steps above.
* Reference this template, <> are placeholders you can change:
```
curl -X POST http://localhost:8080 \
		-H "Host: dispatcher.default.127.0.0.1.nip.io" \
		-H "Content-Type: application/json" \
		-d '{"token":"<your input query to model>","par":{"<parameter1>":<value1>,"<parameter1>":<value2>,...},"env": {"MODEL_ID":"<model ids listed in https://hf.co/models , ex. meta-llama/Meta-Llama-3.1-8B>", "<env2>":<value2>,....,"HF_TOKEN":"$(HF_TOKEN)"}}'

```
* Reference for parameters: https://huggingface.co/docs/transformers/main_classes/text_generation
* Reference for envs : https://huggingface.co/docs/text-generation-inference/main/en/reference/launcher


