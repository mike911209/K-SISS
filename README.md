# SSIS: Scalable Serving Inference System

## About
This project presents a Kubernetes-based serving system for language models, leveraging NVIDIA
Multi-Instance GPU (MIG) and Multi-Process Service technology to partition GPU resources into multiple instances. This
approach enables flexible, fine-grained allocation of GPU slices tailored to the performance demands
of large language model (LLM) inference, optimizing resource utilization and enhancing throughput. Built on
Kubernetes, the system supports efficient auto-scaling to respond dynamically to varying workloads,
ensuring robust resource management adaptability. Additionally, by integrating Hugging Face’s Text Gener-
ation Inference (TGI) framework, the system offers comprehensive LLM inference services with accelerated
performance. 

### Project Structure
The project is composed by three major components : Dispatcher(Serving Manager), Prometheus(Metric Scraper), and Autoscaler.
* Dispatcher is reponsible for handling request, launching service pods, and forwarding request to the pod.
* Autoscaler scales existing running pods by referencing metrics scraped from Prometheus.
* Prometheus monitors performance metrics for running pods.
<img width="852" alt="project structure" src="https://github.com/user-attachments/assets/3916ad97-5989-4fe1-9e91-88eb8574836c" />


## Prerequisites
* A Kubernetes cluster with version > 1.28
* Nodes with MIG or MPS capable GPUs

## Getting Start

### 1. Setup MIG Resources to k8s Cluster

#### Clean Up Existing Environment

1. In Master node, delete existing GPU device plugin if any.
2. Login to worker node.
3. Run `sudo systemctl stop nvidia-persistenced` to stop NVIDIA Persistence Daemon running on the node.
4. Run `sudo systemctl stop nvidia-dcgm` to stop dcgm processes.
5. Use `sudo lsof /dev/nvidia* ` to check if this command has empty output, which means there are no process running on the device.

#### Partition MIG slice

1. Login to worker node
2. You can partition GPU slices through the command：
```
sudo nvidia-smi mig -i 0 -cgi <slice name 1>,<slice name 2>,...  -C
```
* Valid Slice type are listed below: 
```
| Slice name |   SM   | Memory | Cache | Max Count |
|------------|--------|--------|-------|-----------|
|   7g.40gb  | 7 GPC  | 40 GB  | Full  | 1         |
|   4g.20gb  | 4 GPC  | 20 GB  | 4/8   | 1         |
|   3g.20gb  | 3 GPC  | 20 GB  | 4/8   | 2         |
|   2g.10gb  | 2 GPC  | 10 GB  | 2/8   | 3         |
|   1g.5gb   | 1 GPC  | 5 GB   | 1/8   | 7         |
```

* You can find the valid GPU slice combinations in [here](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/#a100-mig-profiles)


#### Set Up MIG device plugin for Kubernetes

* Install [NVIDIA gpu-operator](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/index.html) device plugin, with the below parameters set:
```
helm install --wait --generate-name \
-n gpu-operator --create-namespace \
nvidia/gpu-operator \
--set mig.strategy=mixed \
--set migManager.config.name=custom-mig-parted-config
```

#### Check MIG setup
* Wait a while for `gpu-operator` to be ready and running.
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

#### Project Structure
```
Dispatcher/
├── .github/
│   └── workflows/           # GitHub Actions workflows (CI/CD)
├── test/                    # Test files or test data
├── assigner.go              # Luanching Knative Service and Forwarding Request
├── config.go                # Dispatcher configurations
├── configuration.yaml       # YAML kubernetes config file 
├── Dockerfile               # Docker container specification
├── go.mod                   # Go module definition
├── go.sum                   # Go module checksums
├── LICENSE                  # License information
├── main.go                  # Entry point of the application
├── makefile                 # Build, Deploy, and Test automation commands
├── preprocessor.go          # Request pre-processes customization (default empty)
├── processor.go             # Main processing logic (covering resource provisioning, resource allocation descision)
├── README.md                # Subproject documentation
└── request.go               # Handles request parsing/structs

```

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
* Make sure you are in the Dispatcher subproject directory
* Run `make setup_knative` to install knative environment, ingress, and load balancer.
* `k get po -n kourier-system`, check if kourier gateway is running.
* `k get svc -n kourier-system`, check if kourier svc and kourier-internal service is established.
* You can use `curl <kourier service external ip>` to test kourier external gateway or run a pod on cluster that runs `curl http://kourier-internal.kourier-system.svc.cluster.local` to check the in-cluster gateway is operating

#### 2. Build Your Own Dispatcher Image

* Run `make build`

#### 3. Deploy dispatcher

* Run `make deploy`

#### 4. Forward kourier in-cluster gateway 

* Assume the cluster external ip is unavailable, we make our test using in-cluster ip, which is likely available in most cases

* Open another terminal window , then : `make forward`

#### 5. Send test API request to Dispatcher
* Export your HuggingFace token : `export HF_TOKEN="<Your token>"`
* Change Directory to `/test` and install required python package through `pip install -r requirements.txt`
* Run `python test.py` to send sample request to Dispatcher

#### Uninstalling Dispatcher 
* Delete all knative service running
* Run `make clean` to remove dispatcher
* Run `make remove_knative` to remove knative

### 2. Setup Autoascaler

#### About

K-SISS Autoscaler is an GPU-aware autoscaler for inference workloads (e.g., LLMs) deployed in Knative and Kubernetes.  
It adjusts GPU resource tiers (MIG, MPS, or full GPU) dynamically based on application metrics like latency and throughput.

#### Features

- **Dynamic GPU Tier Scaling** — supports MIG, MPS, and full GPU
- **Metric-Based Decisions** — driven by Prometheus metrics (e.g., latency, tokens/sec)
- **Knative + Prometheus Integration** — integrated with Knatie and Prometheus

#### Build & Run
> Make sure to configure the `makefile` for your Docker or GitHub container registry.

**Please run the following command under `Autoscaler` directory.**

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

### 3. Setup Prometheus and Prometheus support
#### Install prometheus
Check prometheus have beeb installed in k8s cluster.

#### Install SSIS Promsupp (Prometheus support)
**Please run the following command under `Promsupp` directory**

Promsupp is an SSIS subproject that connects Prometheus with SSIS applications by creating Services and ServiceMonitors for metric scraping.

Build your image:
```
make build
```

Edit configuration.yaml to match your environment (e.g., namespace).

Deploy into you k8s cluster:
```
make deploy
```
>  This will use configuration.yaml to deploy the autoscaler

### 4. Send Request to SSIS

#### Send Customize request to Dispatcher
* Make sure you done all steps above.
* You can set custom request through modifying `Dispatcher/test/payload.json`(then run `test.py` again):
```
{
    "token": "What is Deep Learning?",
    "par": {
        "max_new_tokens": "20"
    },
    "env": {
        "MODEL_ID": "openai-community/gpt2",
        "HF_TOKEN": ""
    }
}
``` 
* Reference for parameters (par): https://huggingface.co/docs/transformers/main_classes/text_generation
* Reference for environment variables (env) : https://huggingface.co/docs/text-generation-inference/main/en/reference/launcher
