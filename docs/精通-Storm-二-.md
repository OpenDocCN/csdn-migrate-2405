# 精通 Storm（二）

> 原文：[`zh.annas-archive.org/md5/5A2D98C1AAE9E2E2F9D015883F441239`](https://zh.annas-archive.org/md5/5A2D98C1AAE9E2E2F9D015883F441239)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：Storm 调度程序

在前几章中，我们介绍了 Storm 的基础知识，Storm 的安装，Storm 的开发和部署，以及 Storm 集群中的 Trident 拓扑。在本章中，我们将专注于 Storm 调度程序。

在本章中，我们将涵盖以下要点：

+   Storm 调度程序介绍

+   默认调度程序

+   隔离调度程序

+   资源感知调度程序

+   客户感知调度程序

# Storm 调度程序介绍

如前两章所述，Nimbus 负责部署拓扑，监督者负责执行 Storm 拓扑的 spouts 和 bolts 组件中定义的计算任务。正如我们所展示的，我们可以根据调度程序策略为每个监督者节点配置分配给拓扑的工作插槽数量，以及为拓扑分配的工作节点数量。简而言之，Storm 调度程序帮助 Nimbus 决定任何给定拓扑的工作分配。

# 默认调度程序

Storm 默认调度程序在给定拓扑分配的所有工作节点（监督者插槽）之间尽可能均匀地分配组件执行器。

让我们考虑一个包含一个 spout 和一个 bolt 的示例拓扑，两个组件都有两个执行器。如果我们通过分配两个工作节点（监督者插槽）提交了拓扑，下图显示了执行器的分配：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00041.gif)

如前图所示，每个工作节点包含一个 spout 的执行器和一个 bolt 的执行器。只有当每个组件中的执行器数量可以被分配给拓扑的工作节点数量整除时，才能在工作节点之间均匀分配执行器。

# 隔离调度程序

隔离调度程序提供了一种在许多拓扑之间轻松安全地共享 Storm 集群资源的机制。隔离调度程序有助于在 Storm 集群中为拓扑分配/保留专用的 Storm 节点集。

我们需要在 Nimbus 配置文件中定义以下属性以切换到隔离调度程序：

```scala
storm.scheduler: org.apache.storm.scheduler.IsolationScheduler 
```

我们可以通过在`isolation.scheduler.machines`属性中指定拓扑名称和节点数量来为任何拓扑分配/保留资源，如下一节所述。我们需要在 Nimbus 配置中定义`isolation.scheduler.machines`属性，因为 Nimbus 负责在 Storm 节点之间分配拓扑工作节点：

```scala
isolation.scheduler.machines:  
  "Topology-Test1": 2 
  "Topology-Test2": 1 
  "Topology-Test3": 4 
```

在上述配置中，`Topology-Test1`分配了两个节点，`Topology-Test2`分配了一个节点，`Topology-Test3`分配了四个节点。

以下是隔离调度程序的关键要点：

+   隔离列表中提到的拓扑优先于非隔离拓扑，这意味着如果与非隔离拓扑竞争，资源将首先分配给隔离拓扑

+   在运行时没有办法更改拓扑的隔离设置。

+   隔离调度程序通过为拓扑分配专用机器来解决多租户问题

# 资源感知调度程序

资源感知调度程序帮助用户指定单个组件实例（spout 或 bolt）所需的资源量。我们可以通过在`storm.yaml`文件中指定以下属性来启用资源感知调度程序：

```scala
storm.scheduler: "org.apache.storm.scheduler.resource.ResourceAwareScheduler" 
```

# 组件级配置

您可以为任何组件分配内存需求。以下是可用于为任何组件的单个实例分配内存的方法：

```scala
public T setMemoryLoad(Number onHeap, Number offHeap) 
```

或者，您可以使用以下方法：

```scala
public T setMemoryLoad(Number onHeap) 
```

以下是每个参数的定义：

+   `onHeap`：此组件实例将消耗的堆内存空间量（以兆字节为单位）

+   `offHeap`：此组件实例将消耗的堆外内存空间量（以兆字节为单位）

`onHeap`和`offHeap`的数据类型均为`Number`，默认值为`0.0`。

# 内存使用示例

让我们考虑一个具有两个组件（一个 spout 和一个 bolt）的拓扑：

```scala
SpoutDeclarer spout1 = builder.setSpout("spout1", new spoutComponent(), 4); 
spout1.setMemoryLoad(1024.0, 512.0); 
builder.setBolt("bolt1", new boltComponent(), 5).setMemoryLoad(512.0); 
```

`spout1`组件的单个实例的内存请求为 1.5 GB（堆上 1 GB，堆外 0.5 GB），这意味着`spout1`组件的总内存请求为 4 x 1.5 GB = 6 GB。

`bolt1`组件的单个实例的内存请求为 0.5 GB（堆上 0.5 GB，堆外 0.0 GB），这意味着`bolt1`组件的总内存请求为 5 x 0.5 GB = 2.5 GB。计算两个组件所需的总内存的方法可以总结如下：

*拓扑分配的总内存= spout1 + bolt1 = 6 + 2.5 = 8.5 GB*

您还可以将 CPU 需求分配给任何组件。

以下是为任何给定组件的单个实例分配 CPU 资源量所需的方法：

```scala
public T setCPULoad(Double amount) 
```

`amount`是任何给定组件实例将消耗的 CPU 资源量。 CPU 使用是一个难以定义的概念。不同的 CPU 架构根据手头的任务而表现不同。按照惯例，CPU 核心通常有 100 个点。如果您觉得您的处理器更强大或更弱，可以相应地进行调整。CPU 密集型的重型任务将获得 100 分，因为它们可以占用整个核心。中等任务应该获得 50 分，轻型任务 25 分，微小任务 10 分。

# CPU 使用示例

让我们考虑一个具有两个组件（一个 spout 和一个 bolt）的拓扑：

```scala
SpoutDeclarer spout1 = builder.setSpout("spout1", new spoutComponent(), 4); 
spout1.setCPULoad(15.0); 
builder.setBolt("bolt1", new boltComponent(), 5).setCPULoad(450.0); 
```

# 工作节点级配置

您可以为每个工作节点/插槽分配堆大小。以下是定义每个工作节点的堆大小所需的方法：

```scala
public void setTopologyWorkerMaxHeapSize(Number size) 
```

在这里，`size`是以兆字节为单位的单个工作节点可用的堆空间量。

这是一个例子：

```scala
Config conf = new Config(); 
conf.setTopologyWorkerMaxHeapSize(1024.0); 
```

# 节点级配置

我们可以通过在`storm.yaml`文件中设置以下属性来配置 Storm 节点可以使用的内存和 CPU 量。我们需要在每个 Storm 节点上设置以下属性：

```scala
supervisor.memory.capacity.mb: [amount<Double>] 
supervisor.cpu.capacity: [amount<Double>] 
```

这是一个例子：

```scala
supervisor.memory.capacity.mb: 10480.0 
supervisor.cpu.capacity: 100.0 
```

在这里，`100`表示整个核心，如前面讨论的。

# 全局组件配置

如前一节所述，我们可以通过定义拓扑来为每个组件定义内存和 CPU 需求。用户还可以在`storm.yaml`文件中设置组件的默认资源使用情况。如果我们在代码中定义组件配置，那么代码值将覆盖默认值：

```scala
//default value if on heap memory requirement is not specified for a component  
topology.component.resources.onheap.memory.mb: 128.0 

//default value if off heap memory requirement is not specified for a component  
topology.component.resources.offheap.memory.mb: 0.0 

//default value if CPU requirement is not specified for a component  
topology.component.cpu.pcore.percent: 10.0 

//default value for the max heap size for a worker   
topology.worker.max.heap.size.mb: 768.0 
```

# 自定义调度程序

在 Storm 中，Nimbus 使用调度程序将任务分配给监督者。默认调度程序旨在将计算资源均匀分配给拓扑。在拓扑之间公平性方面表现良好，但用户无法预测 Storm 集群中拓扑组件的放置，即拓扑的哪个组件需要分配给哪个监督者节点。

让我们考虑一个例子。假设我们有一个具有一个 spout 和两个 bolts 的拓扑，每个组件都有一个执行器和一个任务。如果我们将拓扑提交到 Storm 集群，则以下图表显示了拓扑的分布。假设分配给拓扑的工作节点数量为三，Storm 集群中的监督者数量为三：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00042.gif)

假设我们的拓扑中的最后一个 bolt **Bolt2** 需要使用 GPU 而不是 CPU 来处理一些数据，并且只有一个监督者具有 GPU。我们需要编写自己的自定义调度程序来实现将任何组件分配给特定监督者节点的任务。以下是我们需要执行的步骤：

1.  配置监督者节点中的更改。

1.  在组件级别配置设置。

1.  编写自定义调度程序类。

1.  注册自定义调度程序类。

# 配置监督者节点中的更改

Storm 在监督节点的配置中为用户提供了一个字段，用于指定自定义调度元数据。在这种情况下，我们在监督节点中输入`/tag`和它们运行的类型，这是通过在它们的`$STORM_HOME/conf/storm.yaml`文件中的一行配置完成的。例如，每个监督节点的配置应该包含以下内容：

```scala
supervisor.scheduler.meta: 
  type: GPU 
```

在对每个监督节点添加配置更改后，我们需要重新启动监督节点。对于所有非 GPU 机器，您需要使用 CPU 类型。

# 组件级别的配置设置

这一步是在拓扑结构中使用`TopologyBuilder`的主方法中完成的。`ComponentConfigurationDeclarer`有一个叫做`addConfiguration(String config, String value)`的方法，允许添加自定义配置，也就是元数据。在我们的情况下，我们使用这个方法添加类型信息：

```scala
TopologyBuilder builder = new TopologyBuilder(); 
builder.setSpout("spout", new SampleSpout(), 1); builder.setBolt("bolt1", new ExampleBolt1(), 1).shuffleGrouping("spout"); 
builder.setBolt("bolt3", new SampleBolt2(), 1).shuffleGrouping("bolt2").addConfiguration("type", "GPU"); 
```

前面的代码显示我们已经用`type`为`GPU`对`bolt2`组件进行了类型化。

# 编写自定义监督类

我们可以通过实现`org.apache.storm.scheduler.IScheduler`接口来编写我们的`CustomScheduler`类。这个接口包含两个重要的方法：

+   `prepare(Map conf)`：这个方法只是初始化调度程序。

+   `schedule(Topologies topologies, Cluster cluster)`：这个方法包含负责在集群监督节点插槽中进行拓扑工作的逻辑。

`CustomScheduler`包含以下私有方法，负责将工作程序分配给集群监督节点的插槽。

`getSupervisorsByType()`方法返回映射。映射的键表示节点类型（例如，CPU 或 GPU），值包含该类型监督节点的列表：

```scala
    private Map<String, ArrayList<SupervisorDetails>> getSupervisorsByType( 
            Collection<SupervisorDetails> supervisorDetails 
    ) { 
        // A map of type -> supervisors, to help with scheduling of components with specific types 
        Map<String, ArrayList<SupervisorDetails>> supervisorsByType = new HashMap<String, ArrayList<SupervisorDetails>>(); 

        for (SupervisorDetails supervisor : supervisorDetails) { 
            @SuppressWarnings("unchecked") 
            Map<String, String> metadata = (Map<String, String>) supervisor.getSchedulerMeta(); 

            String types; 

            if (metadata == null) { 
                types = unType; 
            } else { 
                types = metadata.get("types"); 

                if (types == null) { 
                    types = unType; 
                } 
            }
```

```scala
            // If the supervisor has types attached to it, handle it by populating the supervisorsByType map. 
            // Loop through each of the types to handle individually 
            for (String type : types.split(",")) { 
                type = type.trim(); 

                if (supervisorsByType.containsKey(type)) { 
                    // If we've already seen this type, then just add the supervisor to the existing ArrayList. 
                    supervisorsByType.get(type).add(supervisor); 
                } else { 
                    // If this type is new, then create a new ArrayList<SupervisorDetails>, 
                    // add the current supervisor, and populate the map's type entry with it. 
                    ArrayList<SupervisorDetails> newSupervisorList = new ArrayList<SupervisorDetails>(); 
                    newSupervisorList.add(supervisor); 
                    supervisorsByType.put(type, newSupervisorList); 
                } 
            } 
        } 

        return supervisorsByType; 
    } 
```

`populateComponentsByType()`方法也返回映射。映射的键表示类型（CPU 或 GPU），值包含需要分配给该类型监督节点的拓扑组件的列表。我们在这里使用一个无类型的类型来将没有类型的组件分组。这样做的目的是有效地处理这些无类型的组件，就像默认调度程序执行分配一样。这意味着没有类型组件的拓扑将以相同的方式成功调度，跨无类型的监督节点没有问题：

```scala
    private <T> void populateComponentsByType( 
            Map<String, ArrayList<String>> componentsByType, 
            Map<String, T> components 
    ) { 
        // Type T can be either Bolt or SpoutSpec, so that this logic can be reused for both component types 
        JSONParser parser = new JSONParser(); 

        for (Entry<String, T> componentEntry : components.entrySet()) { 
            JSONObject conf = null; 

            String componentID = componentEntry.getKey(); 
            T component = componentEntry.getValue(); 

            try { 
                // Get the component's conf irrespective of its type (via java reflection) 
                Method getCommonComponentMethod = component.getClass().getMethod("get_common"); 
                ComponentCommon commonComponent = (ComponentCommon) getCommonComponentMethod.invoke(component); 
                conf = (JSONObject) parser.parse(commonComponent.get_json_conf()); 
            } catch (Exception ex) { 
                ex.printStackTrace(); 
            } 

            String types; 

            // If there's no config, use a fake type to group all untypeged components 
            if (conf == null) { 
                types = unType; 
            } else { 
                types = (String) conf.get("types"); 

                // If there are no types, use a fake type to group all untypeged components 
                if (types == null) { 
                    types = unType; 
                } 
            } 

            // If the component has types attached to it, handle it by populating the componentsByType map. 
            // Loop through each of the types to handle individually 
            for (String type : types.split(",")) { 
                type = type.trim(); 

                if (componentsByType.containsKey(type)) { 
                    // If we've already seen this type, then just add the component to the existing ArrayList. 
                    componentsByType.get(type).add(componentID); 
                } else { 
                    // If this type is new, then create a new ArrayList, 
                    // add the current component, and populate the map's type entry with it. 
                    ArrayList<String> newComponentList = new ArrayList<String>(); 
                    newComponentList.add(componentID); 
                    componentsByType.put(type, newComponentList); 
                } 
            } 
        } 
    } 
```

`populateComponentsByTypeWithStormInternals()`方法返回 Storm 启动的内部组件的详细信息。

```scala
    private void populateComponentsByTypeWithStormInternals( 
            Map<String, ArrayList<String>> componentsByType, 
            Set<String> components 
    ) { 
        // Storm uses some internal components, like __acker. 
        // These components are topology-agnostic and are therefore not accessible through a StormTopology object. 
        // While a bit hacky, this is a way to make sure that we schedule those components along with our topology ones: 
        // we treat these internal components as regular untypeged components and add them to the componentsByType map. 

        for (String componentID : components) { 
            if (componentID.startsWith("__")) { 
                if (componentsByType.containsKey(unType)) { 
                    // If we've already seen untypeged components, then just add the component to the existing ArrayList. 
                    componentsByType.get(unType).add(componentID); 
                } else { 
                    // If this is the first untypeged component we see, then create a new ArrayList, 
                    // add the current component, and populate the map's untypeged entry with it. 
                    ArrayList<String> newComponentList = new ArrayList<String>(); 
                    newComponentList.add(componentID); 
                    componentsByType.put(unType, newComponentList); 
                } 
            } 
        } 
    } 
```

前三种方法管理监督和组件的映射。现在，我们将编写`typeAwareScheduler()`方法，它将使用这两个映射：

```scala
    private void typeAwareSchedule(Topologies topologies, Cluster cluster) { 
        Collection<SupervisorDetails> supervisorDetails = cluster.getSupervisors().values(); 

        // Get the lists of typed and unreserved supervisors. 
        Map<String, ArrayList<SupervisorDetails>> supervisorsByType = getSupervisorsByType(supervisorDetails); 

        for (TopologyDetails topologyDetails : cluster.needsSchedulingTopologies(topologies)) { 
            StormTopology stormTopology = topologyDetails.getTopology(); 
            String topologyID = topologyDetails.getId(); 

            // Get components from topology 
            Map<String, Bolt> bolts = stormTopology.get_bolts(); 
            Map<String, SpoutSpec> spouts = stormTopology.get_spouts(); 

            // Get a map of component to executors 
            Map<String, List<ExecutorDetails>> executorsByComponent = cluster.getNeedsSchedulingComponentToExecutors( 
                    topologyDetails 
            ); 

            // Get a map of type to components 
            Map<String, ArrayList<String>> componentsByType = new HashMap<String, ArrayList<String>>(); 
            populateComponentsByType(componentsByType, bolts); 
            populateComponentsByType(componentsByType, spouts); 
            populateComponentsByTypeWithStormInternals(componentsByType, executorsByComponent.keySet()); 

            // Get a map of type to executors 
            Map<String, ArrayList<ExecutorDetails>> executorsToBeScheduledByType = getExecutorsToBeScheduledByType( 
                    cluster, topologyDetails, componentsByType 
            ); 

            // Initialise a map of slot -> executors 
            Map<WorkerSlot, ArrayList<ExecutorDetails>> componentExecutorsToSlotsMap = ( 
                    new HashMap<WorkerSlot, ArrayList<ExecutorDetails>>() 
            ); 

            // Time to match everything up! 
            for (Entry<String, ArrayList<ExecutorDetails>> entry : executorsToBeScheduledByType.entrySet()) { 
                String type = entry.getKey(); 

                ArrayList<ExecutorDetails> executorsForType = entry.getValue(); 
                ArrayList<SupervisorDetails> supervisorsForType = supervisorsByType.get(type); 
                ArrayList<String> componentsForType = componentsByType.get(type); 

                try { 
                    populateComponentExecutorsToSlotsMap( 
                            componentExecutorsToSlotsMap, 
                            cluster, topologyDetails, supervisorsForType, executorsForType, componentsForType, type 
                    ); 
                } catch (Exception e) { 
                    e.printStackTrace(); 

                    // Cut this scheduling short to avoid partial scheduling. 
                    return; 
                } 
            } 

            // Do the actual assigning 
            // We do this as a separate step to only perform any assigning if there have been no issues so far. 
            // That's aimed at avoiding partial scheduling from occurring, with some components already scheduled 
            // and alive, while others cannot be scheduled. 
            for (Entry<WorkerSlot, ArrayList<ExecutorDetails>> entry : componentExecutorsToSlotsMap.entrySet()) { 
                WorkerSlot slotToAssign = entry.getKey(); 
                ArrayList<ExecutorDetails> executorsToAssign = entry.getValue(); 

                cluster.assign(slotToAssign, topologyID, executorsToAssign); 
            } 

            // If we've reached this far, then scheduling must have been successful 
            cluster.setStatus(topologyID, "SCHEDULING SUCCESSFUL"); 
        } 
    } 
```

除了前面提到的四种方法，我们还使用了更多的方法来执行以下操作。

# 将组件 ID 转换为执行程序

现在让我们从组件 ID 跳转到实际的执行程序，因为这是 Storm 集群处理分配的级别。

这个过程非常简单：

+   从集群获取按组件的执行程序的映射

+   根据集群检查哪些组件的执行程序需要调度

+   创建类型到执行程序的映射，只填充等待调度的执行程序：

```scala
private Set<ExecutorDetails> getAllAliveExecutors(Cluster cluster, TopologyDetails topologyDetails) { 
        // Get the existing assignment of the current topology as it's live in the cluster 
        SchedulerAssignment existingAssignment = cluster.getAssignmentById(topologyDetails.getId()); 

        // Return alive executors, if any, otherwise an empty set 
        if (existingAssignment != null) { 
            return existingAssignment.getExecutors(); 
        } else { 
            return new HashSet<ExecutorDetails>(); 
        } 
    } 

    private Map<String, ArrayList<ExecutorDetails>> getExecutorsToBeScheduledByType( 
            Cluster cluster, 
            TopologyDetails topologyDetails, 
            Map<String, ArrayList<String>> componentsPerType 
    ) { 
        // Initialise the return value 
        Map<String, ArrayList<ExecutorDetails>> executorsByType = new HashMap<String, ArrayList<ExecutorDetails>>(); 

        // Find which topology executors are already assigned 
        Set<ExecutorDetails> aliveExecutors = getAllAliveExecutors(cluster, topologyDetails); 

        // Get a map of component to executors for the topology that need scheduling 
        Map<String, List<ExecutorDetails>> executorsByComponent = cluster.getNeedsSchedulingComponentToExecutors( 
                topologyDetails 
        ); 

        // Loop through componentsPerType to populate the map 
        for (Entry<String, ArrayList<String>> entry : componentsPerType.entrySet()) { 
            String type = entry.getKey(); 
            ArrayList<String> componentIDs = entry.getValue(); 

            // Initialise the map entry for the current type 
            ArrayList<ExecutorDetails> executorsForType = new ArrayList<ExecutorDetails>(); 

            // Loop through this type's component IDs 
            for (String componentID : componentIDs) { 
                // Fetch the executors for the current component ID 
                List<ExecutorDetails> executorsForComponent = executorsByComponent.get(componentID); 

                if (executorsForComponent == null) { 
                    continue; 
                } 

                // Convert the list of executors to a set 
                Set<ExecutorDetails> executorsToAssignForComponent = new HashSet<ExecutorDetails>( 
                        executorsForComponent 
                ); 

                // Remove already assigned executors from the set of executors to assign, if any 
                executorsToAssignForComponent.removeAll(aliveExecutors); 

                // Add the component's waiting to be assigned executors to the current type executors 
                executorsForType.addAll(executorsToAssignForComponent); 
            } 

            // Populate the map of executors by type after looping through all of the type's components, 
            // if there are any executors to be scheduled 
            if (!executorsForType.isEmpty()) { 
                executorsByType.put(type, executorsForType); 
            } 
        } 

        return executorsByType; 
} 
```

# 将监督转换为插槽

现在是我们必须执行的最终转换：从监督到插槽的跳转。与组件及其执行程序一样，我们需要这个，因为集群在插槽级别分配执行程序，而不是监督级别。

在这一点上有一些事情要做；我们已经将这个过程分解成更小的方法来保持可读性。我们需要执行的主要步骤如下：

找出我们可以分配的插槽，给定一个类型的监督节点列表。这只是使用一个 for 循环收集所有监督节点的插槽，然后返回拓扑所请求的插槽数量。

将等待调度的类型的执行程序分成均匀的组。

用条目填充插槽到执行程序的映射。

这里的想法是每种类型调用`populateComponentExecutorsToSlotsMap`方法一次，这将导致一个包含我们需要执行的所有分配的单个映射。

如代码注释中所解释的，我们先前发现有时我们会急切地将类型的执行者分配给一个插槽，只是为了让后续的类型无法分配其执行者，导致部分调度。我们已经确保调度流程确保不会执行部分调度（要么全部被调度，要么全部不被调度），尽管这会增加一个额外的循环，但我们认为这是拓扑结构的更清洁状态：

```scala
    private void handleFailedScheduling( 
            Cluster cluster, 
            TopologyDetails topologyDetails, 
            String message 
    ) throws Exception { 
        // This is the prefix of the message displayed on Storm's UI for any unsuccessful scheduling 
        String unsuccessfulSchedulingMessage = "SCHEDULING FAILED: "; 

        cluster.setStatus(topologyDetails.getId(), unsuccessfulSchedulingMessage + message); 
        throw new Exception(message); 
    } 

    private Set<WorkerSlot> getAllAliveSlots(Cluster cluster, TopologyDetails topologyDetails) { 
        // Get the existing assignment of the current topology as it's live in the cluster 
        SchedulerAssignment existingAssignment = cluster.getAssignmentById(topologyDetails.getId()); 

        // Return alive slots, if any, otherwise an empty set 
        if (existingAssignment != null) { 
            return existingAssignment.getSlots(); 
        } else { 
            return new HashSet<WorkerSlot>(); 
        } 
    } 

    private List<WorkerSlot> getAllSlotsToAssign( 
            Cluster cluster, 
            TopologyDetails topologyDetails, 
            List<SupervisorDetails> supervisors, 
            List<String> componentsForType, 
            String type 
    ) throws Exception { 
        String topologyID = topologyDetails.getId(); 

        // Collect the available slots of each of the supervisors we were given in a list 
        List<WorkerSlot> availableSlots = new ArrayList<WorkerSlot>(); 
        for (SupervisorDetails supervisor : supervisors) { 
            availableSlots.addAll(cluster.getAvailableSlots(supervisor)); 
        } 

        if (availableSlots.isEmpty()) { 
            // This is bad, we have supervisors and executors to assign, but no available slots! 
            String message = String.format( 
                    "No slots are available for assigning executors for type %s (components: %s)", 
                    type, componentsForType 
            ); 
            handleFailedScheduling(cluster, topologyDetails, message); 
        } 

        Set<WorkerSlot> aliveSlots = getAllAliveSlots(cluster, topologyDetails); 

        int numAvailableSlots = availableSlots.size(); 
        int numSlotsNeeded = topologyDetails.getNumWorkers() - aliveSlots.size(); 

        // We want to check that we have enough available slots 
        // based on the topology's number of workers and already assigned slots. 
        if (numAvailableSlots < numSlotsNeeded) { 
            // This is bad, we don't have enough slots to assign to! 
            String message = String.format( 
                    "Not enough slots available for assigning executors for type %s (components: %s). " 
                            + "Need %s slots to schedule but found only %s", 
                    type, componentsForType, numSlotsNeeded, numAvailableSlots 
            ); 
            handleFailedScheduling(cluster, topologyDetails, message); 
        } 

        // Now we can use only as many slots as are required. 
        return availableSlots.subList(0, numSlotsNeeded); 
    } 

    private Map<WorkerSlot, ArrayList<ExecutorDetails>> getAllExecutorsBySlot( 
            List<WorkerSlot> slots, 
            List<ExecutorDetails> executors 
    ) { 
        Map<WorkerSlot, ArrayList<ExecutorDetails>> assignments = new HashMap<WorkerSlot, ArrayList<ExecutorDetails>>(); 

        int numberOfSlots = slots.size(); 

        // We want to split the executors as evenly as possible, across each slot available, 
        // so we assign each executor to a slot via round robin 
        for (int i = 0; i < executors.size(); i++) { 
            WorkerSlot slotToAssign = slots.get(i % numberOfSlots); 
            ExecutorDetails executorToAssign = executors.get(i); 

            if (assignments.containsKey(slotToAssign)) { 
                // If we've already seen this slot, then just add the executor to the existing ArrayList. 
                assignments.get(slotToAssign).add(executorToAssign); 
            } else { 
                // If this slot is new, then create a new ArrayList, 
                // add the current executor, and populate the map's slot entry with it. 
                ArrayList<ExecutorDetails> newExecutorList = new ArrayList<ExecutorDetails>(); 
                newExecutorList.add(executorToAssign); 
                assignments.put(slotToAssign, newExecutorList); 
            } 
        } 

        return assignments; 
    } 

    private void populateComponentExecutorsToSlotsMap( 
            Map<WorkerSlot, ArrayList<ExecutorDetails>> componentExecutorsToSlotsMap, 
            Cluster cluster, 
            TopologyDetails topologyDetails, 
            List<SupervisorDetails> supervisors, 
            List<ExecutorDetails> executors, 
            List<String> componentsForType, 
            String type 
    ) throws Exception { 
        String topologyID = topologyDetails.getId(); 

        if (supervisors == null) { 
            // This is bad, we don't have any supervisors but have executors to assign! 
            String message = String.format( 
                    "No supervisors given for executors %s of topology %s and type %s (components: %s)", 
                    executors, topologyID, type, componentsForType 
            ); 
            handleFailedScheduling(cluster, topologyDetails, message); 
        } 

        List<WorkerSlot> slotsToAssign = getAllSlotsToAssign( 
                cluster, topologyDetails, supervisors, componentsForType, type 
        ); 

        // Divide the executors evenly across the slots and get a map of slot to executors 
        Map<WorkerSlot, ArrayList<ExecutorDetails>> executorsBySlot = getAllExecutorsBySlot( 
                slotsToAssign, executors 
        ); 

        for (Entry<WorkerSlot, ArrayList<ExecutorDetails>> entry : executorsBySlot.entrySet()) { 
            WorkerSlot slotToAssign = entry.getKey(); 
            ArrayList<ExecutorDetails> executorsToAssign = entry.getValue(); 

            // Assign the topology's executors to slots in the cluster's supervisors 
            componentExecutorsToSlotsMap.put(slotToAssign, executorsToAssign); 
        } 
    } 
```

# 注册一个 CustomScheduler 类

我们需要为`CustomScheduler`类创建一个 JAR，并将其放在`$STORM_HOME/lib/`中，并通过将以下行附加到`$STORM_HOME/conf/storm.yaml`配置文件中告诉 Nimbus 使用新的调度程序：

```scala
storm.scheduler: "com.stormadvance.storm_kafka_topology.CustomScheduler" 
```

重新启动 Nimbus 守护程序以反映对配置的更改。

现在，如果我们部署与上一个图中显示的相同的拓扑结构，那么执行者的分布将如下所示（**Bolt2**分配给了一个 GPU 类型的监督者）：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00043.gif)

# 摘要

在本章中，我们了解了内置的 Storm 调度程序，还介绍了如何编写和配置自定义调度程序。

在下一章中，我们将介绍使用 Graphite 和 Ganglia 监视 Storm 集群。


# 第七章：监控 Storm 集群

在之前的章节中，我们学习了如何在远程 Storm 集群上部署拓扑，如何配置拓扑的并行性，不同类型的流分组等。在本章中，我们将专注于如何监视和收集运行在 Storm 集群上的拓扑的统计信息。

在本章中，我们将涵盖以下主题：

+   通过 Nimbus thrift 端口收集 Storm 指标

+   将 Storm 与 Ganglia 集成

+   安装 Graphite

# 使用 Nimbus thrift 客户端收集集群统计信息

本节涵盖了如何使用 Nimbus thrift 客户端收集集群详细信息（类似于 Storm UI 页面上显示的详细信息）。通过 Nimbus thrift 客户端提取/收集信息可以让我们可视化数据。

Nimbus thrift API 非常丰富，可以公开监视 Storm 集群所需的所有必要信息。

# 使用 Nimbus thrift 获取信息

在本节中，我们将使用 Nimbus thrift 客户端创建一个 Java 项目，该项目将包含执行以下操作的类：

+   收集 Nimbus 配置

+   收集监督者统计信息

+   收集拓扑统计信息

+   收集给定拓扑的喷口统计信息

+   收集给定拓扑的螺栓统计信息

+   终止给定的拓扑

以下是使用 Nimbus thrift 客户端获取集群详细信息的步骤：

1.  使用`com.stormadvance`作为`groupId`和`stormmonitoring`作为`artifactId`创建一个 Maven 项目。

1.  将以下依赖项添加到`pom.xml`文件中：

```scala
<dependency> 
  <groupId>org.apache.storm</groupId> 
  <artifactId>storm-core</artifactId> 
  <version>1.0.2</version> 
  <scope>provided</scope> 
</dependency> 

```

1.  在`com.stormadvance`包中创建一个名为`ThriftClient`的实用类。`ThriftClient`类包含逻辑，用于与 Nimbus thrift 服务器建立连接并返回 Nimbus 客户端：

```scala
public class ThriftClient { 
  // IP of the Storm UI node 
  private static final String STORM_UI_NODE = "127.0.0.1"; 
  public Client getClient() { 
    // Set the IP and port of thrift server. 
    // By default, the thrift server start on port 6627 
    TSocket socket = new TSocket(STORM_UI_NODE, 6627); 
    TFramedTransport tFramedTransport = new TFramedTransport(socket); 
    TBinaryProtocol tBinaryProtocol = new TBinaryProtocol(tFramedTransport); 
    Client client = new Client(tBinaryProtocol); 
    try { 
      // Open the connection with thrift client. 
      tFramedTransport.open(); 
    }catch(Exception exception) { 
      throw new RuntimeException("Error occurs while making connection with Nimbus thrift server"); 
    } 
    // return the Nimbus Thrift client. 
    return client;           
  } 
} 
```

1.  让我们在`com.stormadvance`包中创建一个名为`NimbusConfiguration`的类。该类包含使用 Nimbus 客户端收集 Nimbus 配置的逻辑：

```scala
public class NimbusConfiguration { 

  public void printNimbusStats() { 
    try { 
      ThriftClient thriftClient = new ThriftClient(); 
      Client client = thriftClient.getClient(); 
      String nimbusConiguration = client.getNimbusConf(); 
      System.out.println("*************************************"); 
      System.out.println("Nimbus Configuration : "+nimbusConiguration); 
      System.out.println("*************************************"); 
    }catch(Exception exception) { 
      throw new RuntimeException("Error occure while fetching the Nimbus statistics : "); 
    } 
  }

  public static void main(String[] args) { 
    new NimbusConfiguration().printNimbusStats(); 
  }      
}
```

上述代码使用`org.apache.storm.generated.Nimbus.Client`类的`getNimbusConf()`方法来获取 Nimbus 配置。

1.  在`com.stormadvance`包中创建一个名为`SupervisorStatistics`的类，以收集 Storm 集群中所有监督者节点的信息：

```scala
public class SupervisorStatistics { 

  public void printSupervisorStatistics()  { 
    try { 
      ThriftClient thriftClient = new ThriftClient(); 
      Client client = thriftClient.getClient(); 
      // Get the cluster information. 
      ClusterSummary clusterSummary = client.getClusterInfo(); 
      // Get the SupervisorSummary iterator 
      Iterator<SupervisorSummary> supervisorsIterator = clusterSummary.get_supervisors_iterator(); 

      while (supervisorsIterator.hasNext()) { 
        // Print the information of supervisor node 
        SupervisorSummary supervisorSummary = (SupervisorSummary) supervisorsIterator.next();

        System.out.println("*************************************"); 
        System.out.println("Supervisor Host IP : "+supervisorSummary.get_host()); 
        System.out.println("Number of used workers : "+supervisorSummary.get_num_used_workers()); 
        System.out.println("Number of workers : "+supervisorSummary.get_num_workers()); 
        System.out.println("Supervisor ID : "+supervisorSummary.get_supervisor_id()); 
        System.out.println("Supervisor uptime in seconds : "+supervisorSummary.get_uptime_secs());

        System.out.println("*************************************"); 
      } 

    }catch (Exception e) { 
      throw new RuntimeException("Error occure while getting cluster info : "); 
    } 
  } 

} 
```

`SupervisorStatistics`类使用`org.apache.storm.generated.Nimbus.Client`类的`getClusterInfo()`方法来收集集群摘要，然后调用`org.apache.storm.generated.ClusterSummary`类的`get_supervisors_iterator()`方法来获取`org.apache.storm.generated.SupervisorSummary`类的迭代器。

请参阅`SupervisorStatistics`类的输出。

**![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00044.jpeg)**

1.  在`com.stormadvance`包中创建一个名为`TopologyStatistics`的类，以收集 Storm 集群中所有运行拓扑的信息：

```scala
public class TopologyStatistics { 

  public void printTopologyStatistics() { 
    try { 
      ThriftClient thriftClient = new ThriftClient(); 
      // Get the thrift client 
      Client client = thriftClient.getClient(); 
      // Get the cluster info 
      ClusterSummary clusterSummary = client.getClusterInfo(); 
      // Get the iterator over TopologySummary class 
      Iterator<TopologySummary> topologiesIterator = clusterSummary.get_topologies_iterator(); 
      while (topologiesIterator.hasNext()) { 
        TopologySummary topologySummary = topologiesIterator.next();

        System.out.println("*************************************"); 
        System.out.println("ID of topology: " + topologySummary.get_id()); 
        System.out.println("Name of topology: " + topologySummary.get_name()); 
        System.out.println("Number of Executors: " + topologySummary.get_num_executors()); 
        System.out.println("Number of Tasks: " + topologySummary.get_num_tasks()); 
        System.out.println("Number of Workers: " + topologySummary.get_num_workers()); 
        System.out.println("Status of toplogy: " + topologySummary.get_status()); 
        System.out.println("Topology uptime in seconds: " + topologySummary.get_uptime_secs());

        System.out.println("*************************************"); 
      } 
    }catch (Exception exception) { 
      throw new RuntimeException("Error occure while fetching the topolgies  information"); 
    } 
  }      
} 
```

`TopologyStatistics`类使用`org.apache.storm.generated.ClusterSummary`类的`get_topologies_iterator()`方法来获取`org.apache.storm.generated.TopologySummary`类的迭代器。`TopologyStatistics`类将打印每个拓扑分配的执行器数量、任务数量和工作进程数量的值。

1.  在`com.stormadvance`包中创建一个名为`SpoutStatistics`的类，以获取喷口的统计信息。`SpoutStatistics`类包含一个名为`printSpoutStatistics(String topologyId)`的方法，用于打印给定拓扑提供的所有喷口的详细信息：

```scala
public class SpoutStatistics { 

  private static final String DEFAULT = "default"; 
  private static final String ALL_TIME = ":all-time"; 

  public void printSpoutStatistics(String topologyId) { 
    try { 
      ThriftClient thriftClient = new ThriftClient(); 
      // Get the nimbus thrift client 
      Client client = thriftClient.getClient(); 
      // Get the information of given topology  
      TopologyInfo topologyInfo = client.getTopologyInfo(topologyId);          
      Iterator<ExecutorSummary> executorSummaryIterator = topologyInfo.get_executors_iterator(); 
      while (executorSummaryIterator.hasNext()) { 
        ExecutorSummary executorSummary = executorSummaryIterator.next(); 
        ExecutorStats executorStats = executorSummary.get_stats(); 
        if(executorStats !=null) { 
          ExecutorSpecificStats executorSpecificStats = executorStats.get_specific(); 
          String componentId = executorSummary.get_component_id(); 
          //  
          if (executorSpecificStats.is_set_spout()) { 
            SpoutStats spoutStats = executorSpecificStats.get_spout();

             System.out.println("*************************************"); 
            System.out.println("Component ID of Spout:- " + componentId); 
            System.out.println("Transferred:- " + getAllTimeStat(executorStats.get_transferred(),ALL_TIME)); 
            System.out.println("Total tuples emitted:- " + getAllTimeStat(executorStats.get_emitted(), ALL_TIME)); 
            System.out.println("Acked: " + getAllTimeStat(spoutStats.get_acked(), ALL_TIME)); 
            System.out.println("Failed: " + getAllTimeStat(spoutStats.get_failed(), ALL_TIME));
             System.out.println("*************************************"); 
          } 
        } 
      } 
    }catch (Exception exception) { 
      throw new RuntimeException("Error occure while fetching the spout information : "+exception); 
    } 
  } 

  private static Long getAllTimeStat(Map<String, Map<String, Long>> map, String statName) { 
    if (map != null) { 
      Long statValue = null; 
      Map<String, Long> tempMap = map.get(statName); 
      statValue = tempMap.get(DEFAULT); 
      return statValue; 
    } 
    return 0L; 
  } 

  public static void main(String[] args) { 
    new SpoutStatistics().printSpoutStatistics("StormClusterTopology-1-1393847956"); 
  } 
}      
```

上述类使用`org.apache.storm.generated.Nimbus.Client`类的`getTopologyInfo(topologyId)`方法来获取给定拓扑的信息。`SpoutStatistics`类打印喷口的以下统计信息：

+   +   喷口 ID

+   发射的元组数量

+   失败的元组数量

+   确认的元组数量

1.  在`com.stormadvance`包中创建一个`BoltStatistics`类，以获取螺栓的统计信息。`BoltStatistics`类包含一个`printBoltStatistics(String topologyId)`方法，用于打印给定拓扑提供的所有螺栓的信息：

```scala
public class BoltStatistics { 

  private static final String DEFAULT = "default"; 
  private static final String ALL_TIME = ":all-time"; 

  public void printBoltStatistics(String topologyId) { 

    try { 
      ThriftClient thriftClient = new ThriftClient(); 
      // Get the Nimbus thrift server client 
      Client client = thriftClient.getClient(); 

      // Get the information of given topology 
      TopologyInfo topologyInfo = client.getTopologyInfo(topologyId); 
      Iterator<ExecutorSummary> executorSummaryIterator = topologyInfo.get_executors_iterator(); 
      while (executorSummaryIterator.hasNext()) { 
        // get the executor 
        ExecutorSummary executorSummary = executorSummaryIterator.next(); 
        ExecutorStats executorStats = executorSummary.get_stats(); 
        if (executorStats != null) { 
          ExecutorSpecificStats executorSpecificStats = executorStats.get_specific(); 
          String componentId = executorSummary.get_component_id(); 
          if (executorSpecificStats.is_set_bolt()) { 
            BoltStats boltStats = executorSpecificStats.get_bolt();

            System.out.println("*************************************"); 
            System.out.println("Component ID of Bolt " + componentId); 
            System.out.println("Transferred: " + getAllTimeStat(executorStats.get_transferred(), ALL_TIME)); 
            System.out.println("Emitted: " + getAllTimeStat(executorStats.get_emitted(), ALL_TIME)); 
            System.out.println("Acked: " + getBoltStats(boltStats.get_acked(), ALL_TIME)); 
            System.out.println("Failed: " + getBoltStats(boltStats.get_failed(), ALL_TIME)); 
            System.out.println("Executed : " + getBoltStats(boltStats.get_executed(), ALL_TIME));
            System.out.println("*************************************"); 
          } 
        } 
      } 
    } catch (Exception exception) { 
      throw new RuntimeException("Error occure while fetching the bolt information :"+exception); 
    } 
  } 

  private static Long getAllTimeStat(Map<String, Map<String, Long>> map, String statName) { 
    if (map != null) { 
      Long statValue = null; 
      Map<String, Long> tempMap = map.get(statName); 
      statValue = tempMap.get(DEFAULT); 
      return statValue; 
    } 
    return 0L; 
  } 

  public static Long getBoltStats(Map<String, Map<GlobalStreamId, Long>> map, String statName) { 
    if (map != null) { 
      Long statValue = null; 
      Map<GlobalStreamId, Long> tempMap = map.get(statName); 
      Set<GlobalStreamId> key = tempMap.keySet(); 
      if (key.size() > 0) { 
        Iterator<GlobalStreamId> iterator = key.iterator(); 
        statValue = tempMap.get(iterator.next()); 
      } 
      return statValue; 
    } 
    return 0L; 
  }
```

```scala

  public static void main(String[] args) { new BoltStatistics().printBoltStatistics("StormClusterTopology-1-1393847956"); 
}  
```

前面的类使用`backtype.storm.generated.Nimbus.Client`类的`getTopologyInfo(topologyId)`方法来获取给定拓扑的信息。`BoltStatistics`类打印了以下螺栓的统计信息：

+   +   螺栓 ID

+   发射的元组数量

+   元组失败的数量

+   确认的元组数量

1.  在`com.stormadvance`包中创建一个`killTopology`类，并按照以下所述定义一个`kill`方法：

```scala
public void kill(String topologyId) { 
  try { 
    ThriftClient thriftClient = new ThriftClient(); 
    // Get the Nimbus thrift client 
    Client client = thriftClient.getClient(); 
    // kill the given topology 
    client.killTopology(topologyId); 

  }catch (Exception exception) { 
    throw new RuntimeException("Error occure while fetching the spout information : "+exception); 
  } 
} 

public static void main(String[] args) { 
  new killTopology().kill("topologyId"); 
} 
```

前面的类使用`org.apache.storm.generated.Nimbus.Client`类的`killTopology(topologyId)`方法来终止拓扑。

在本节中，我们介绍了使用 Nimbus thrift 客户端收集 Storm 集群指标/详情的几种方法。

# 使用 JMX 监控 Storm 集群

本节将解释如何使用**Java 管理扩展**（**JMX**）监控 Storm 集群。 JMX 是一组用于管理和监控在 JVM 中运行的应用程序的规范。我们可以在 JMX 控制台上收集或显示 Storm 指标，例如堆大小、非堆大小、线程数、加载的类数、堆和非堆内存、虚拟机参数和托管对象。以下是我们使用 JMX 监控 Storm 集群需要执行的步骤：

1.  我们需要在每个监督者节点的`storm.yaml`文件中添加以下行以在每个监督者节点上启用 JMX：

```scala
supervisor.childopts: -verbose:gc -XX:+PrintGCTimeStamps - XX:+PrintGCDetails -Dcom.sun.management.jmxremote - Dcom.sun.management.jmxremote.ssl=false - Dcom.sun.management.jmxremote.authenticate=false - Dcom.sun.management.jmxremote.port=12346   
```

这里，`12346`是通过 JMX 收集监督者 JVM 指标的端口号。

1.  在 Nimbus 机器的`storm.yaml`文件中添加以下行以在 Nimbus 节点上启用 JMX：

```scala
nimbus.childopts: -verbose:gc -XX:+PrintGCTimeStamps - XX:+PrintGCDetails -Dcom.sun.management.jmxremote - Dcom.sun.management.jmxremote.ssl=false - Dcom.sun.management.jmxremote.authenticate=false - Dcom.sun.management.jmxremote.port=12345
```

这里，`12345`是通过 JMX 收集 Nimbus JVM 指标的端口号。

1.  此外，您可以通过在每个监督者节点的`storm.yaml`文件中添加以下行来收集工作进程的 JVM 指标：

```scala
worker.childopts: -verbose:gc -XX:+PrintGCTimeStamps - XX:+PrintGCDetails -Dcom.sun.management.jmxremote - Dcom.sun.management.jmxremote.ssl=false - Dcom.sun.management.jmxremote.authenticate=false - Dcom.sun.management.jmxremote.port=2%ID%   
```

这里，`％ID％`表示工作进程的端口号。如果工作进程的端口是`6700`，则其 JVM 指标将发布在端口号`26700`（`2％ID％`）上。

1.  现在，在安装了 Java 的任何机器上运行以下命令以启动 JConsole：

```scala
cd $JAVA_HOME ./bin/jconsole
```

以下截图显示了我们如何使用 JConsole 连接到监督者 JMX 端口：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00045.jpeg)

如果您在监督者机器之外的机器上打开 JMX 控制台，则需要在上述截图中使用监督者机器的 IP 地址，而不是`127.0.0.1`。

现在，单击“连接”按钮以查看监督者节点的指标。以下截图显示了 JMX 控制台上 Storm 监督者节点的指标：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00046.jpeg)

同样，您可以通过在 JMX 控制台上指定 Nimbus 机器的 IP 地址和 JMX 端口来收集 Nimbus 节点的 JVM 指标。

以下部分将解释如何在 Ganglia 上显示 Storm 集群指标。

# 使用 Ganglia 监控 Storm 集群

Ganglia 是一个监控工具，用于收集集群上运行的不同类型进程的指标。在大多数应用程序中，Ganglia 被用作集中监控工具，用于显示集群上运行的所有进程的指标。因此，通过 Ganglia 启用 Storm 集群的监控至关重要。

Ganglia 有三个重要组件：

+   **Gmond**：这是 Ganglia 的监控守护程序，用于收集节点的指标并将此信息发送到 Gmetad 服务器。要收集每个 Storm 节点的指标，您需要在每个节点上安装 Gmond 守护程序。

+   **Gmetad**：这从所有 Gmond 节点收集指标并将它们存储在循环数据库中。

+   **Ganglia Web 界面**：以图形形式显示指标信息。

Storm 没有内置支持使用 Ganglia 监视 Storm 集群。但是，使用 JMXTrans，您可以启用使用 Ganglia 监视 Storm。JMXTrans 工具允许您连接到任何 JVM，并在不编写一行代码的情况下获取其 JVM 指标。通过 JMX 公开的 JVM 指标可以使用 JMXTrans 在 Ganglia 上显示。因此，JMXTrans 充当了 Storm 和 Ganglia 之间的桥梁。

以下图表显示了 JMXTrans 在 Storm 节点和 Ganglia 之间的使用方式：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00047.jpeg)

执行以下步骤设置 JMXTrans 和 Ganglia：

1.  运行以下命令在每个 Storm 节点上下载并安装 JMXTrans 工具：

```scala
wget https://jmxtrans.googlecode.com/files/jmxtrans-239-0.noarch. rpm sudo rpm -i jmxtrans-239-0.noarch.rpm
```

1.  运行以下命令在网络中的任何机器上安装 Ganglia Gmond 和 Gmetad 包。您可以在不属于 Storm 集群的机器上部署 Gmetad 和 Gmond 进程：

```scala
sudo yum -q -y install rrdtool sudo yum -q -y install ganglia-gmond sudo yum -q -y install ganglia-gmetad sudo yum -q -y install ganglia-web
```

1.  编辑`gmetad.conf`配置文件中的以下行，该文件位于 Gmetad 进程的`/etc/ganglia`中。我们正在编辑此文件以指定数据源的名称和 Ganglia Gmetad 机器的 IP 地址：

```scala
data_source "stormcluster" 127.0.0.1
```

您可以将`127.0.0.1`替换为 Ganglia Gmetad 机器的 IP 地址。

1.  编辑`gmond.conf`配置文件中的以下行，该文件位于 Gmond 进程的`/etc/ganglia`中：

```scala
cluster { 
  name = "stormcluster" 
  owner = "clusterOwner" 
  latlong = "unspecified" 
  url = "unspecified" 
  }
  host { 
    location = "unspecified" 
  }
  udp_send_channel { 
    host = 127.0.0.1 
    port = 8649 
    ttl = 1 
  }
  udp_recv_channel { 
    port = 8649 
  }
```

这里，`127.0.0.1`是 Storm 节点的 IP 地址。您需要将`127.0.0.1`替换为实际机器的 IP 地址。我们主要编辑了 Gmond 配置文件中的以下条目：

+   +   集群名称

+   `udp_send`通道中的主 Gmond 节点的主机地址

+   `udp_recv`通道中的端口

1.  编辑`ganglia.conf`文件中的以下行，该文件位于`/etc/httpd/conf.d`。我们正在编辑`ganglia.conf`文件以启用从所有机器访问 Ganglia UI：

```scala
Alias /ganglia /usr/share/ganglia <Location /ganglia>Allow from all</Location>
```

`ganglia.conf`文件可以在安装 Ganglia web 前端应用程序的节点上找到。在我们的情况下，Ganglia web 界面和 Gmetad 服务器安装在同一台机器上。

1.  运行以下命令启动 Ganglia Gmond、Gmetad 和 web UI 进程：

```scala
sudo service gmond start setsebool -P httpd_can_network_connect 1 sudo service gmetad start sudo service httpd stop sudo service httpd start
```

1.  现在，转到`http://127.0.0.1/ganglia`验证 Ganglia 的安装，并将`127.0.0.1`替换为 Ganglia web 界面机器的 IP 地址。

1.  现在，您需要在每个监督者节点上编写一个`supervisor.json`文件，以使用 JMXTrans 收集 Storm 监督者节点的 JVM 指标，然后使用`com.googlecode.jmxtrans.model.output.GangliaWriter OutputWriters`类将其发布在 Ganglia 上。`com.googlecode.jmxtrans.model.output.GangliaWriter OutputWriters`类用于处理输入的 JVM 指标并将其转换为 Ganglia 使用的格式。以下是`supervisor.json` JSON 文件的内容：

```scala
{ 
  "servers" : [ { 
    "port" : "12346", 
    "host" : "IP_OF_SUPERVISOR_MACHINE", 
    "queries" : [ { 
      "outputWriters": [{ 
        "@class": 
        "com.googlecode.jmxtrans.model.output.GangliaWriter", "settings": { 
          "groupName": "supervisor", 
          "host": "IP_OF_GANGLIA_GMOND_SERVER", 
          "port": "8649" } 
      }], 
      "obj": "java.lang:type=Memory", 
      "resultAlias": "supervisor", 
      "attr": ["ObjectPendingFinalizationCount"] 
    }, 
    { 
      "outputWriters": [{ 
        "@class": 
        "com.googlecode.jmxtrans.model.output.GangliaWriter", "settings" { 
          "groupName": " supervisor ", 
          "host": "IP_OF_GANGLIA_GMOND_SERVER", 
          "port": "8649" 
        } 
      }], 
      "obj": "java.lang:name=Copy,type=GarbageCollector", 
      "resultAlias": " supervisor ", 
      "attr": [ 
        "CollectionCount", 
        "CollectionTime"  
      ] 
    }, 
    { 
      "outputWriters": [{ 
        "@class": 
        "com.googlecode.jmxtrans.model.output.GangliaWriter", "settings": { 
          "groupName": "supervisor ", 
          "host": "IP_OF_GANGLIA_GMOND_SERVER", 
          "port": "8649" 
        } 
      }], 
      "obj": "java.lang:name=Code Cache,type=MemoryPool", 
      "resultAlias": "supervisor ", 
      "attr": [ 
        "CollectionUsageThreshold", 
        "CollectionUsageThresholdCount", 
        "UsageThreshold", 
        "UsageThresholdCount" 
      ] 
    }, 
    { 
      "outputWriters": [{ 
        "@class": 
        "com.googlecode.jmxtrans.model.output.GangliaWriter", "settings": { 
          "groupName": "supervisor ", 
          "host": "IP_OF_GANGLIA_GMOND_SERVER", 
          "port": "8649" 
        } 
      }], 
      "obj": "java.lang:type=Runtime", 
      "resultAlias": "supervisor", 
      "attr": [ 
        "StartTime", 
        "Uptime" 
      ] 
    }
    ], 
    "numQueryThreads" : 2 
  }] 
} 
```

这里，`12346`是`storm.yaml`文件中指定的监督者的 JMX 端口。

您需要将`IP_OF_SUPERVISOR_MACHINE`的值替换为监督机器的 IP 地址。如果集群中有两个监督者，那么节点 1 的`supervisor.json`文件包含节点 1 的 IP 地址，节点 2 的`supervisor.json`文件包含节点 2 的 IP 地址。

您需要将`IP_OF_GANGLIA_GMOND_SERVER`的值替换为 Ganglia Gmond 服务器的 IP 地址。

1.  在 Nimbus 节点上创建`nimbus.json`文件。使用 JMXTrans，收集 Storm Nimbus 进程的 JVM 指标，并使用`com.googlecode.jmxtrans.model.output.GangliaWriter OutputWriters`类将其发布在 Ganglia 上。以下是`nimbus.json`文件的内容：

```scala
{ 
  "servers" : [{ 
    "port" : "12345", 
    "host" : "IP_OF_NIMBUS_MACHINE", 
    "queries" : [ 
      { "outputWriters": [{ 
        "@class": 
        "com.googlecode.jmxtrans.model.output.GangliaWriter", 
        "settings": { 
          "groupName": "nimbus", 
          "host": "IP_OF_GANGLIA_GMOND_SERVER", 
          "port": "8649" 
        } 
      }], 
      "obj": "java.lang:type=Memory", 
      "resultAlias": "nimbus", 
      "attr": ["ObjectPendingFinalizationCount"] 
      }, 
      { 
        "outputWriters": [{ 
          "@class": 
          "com.googlecode.jmxtrans.model.output.GangliaWriter", "settings": { 
            "groupName": "nimbus", 
            "host": "IP_OF_GANGLIA_GMOND_SERVER", 
            "port": "8649" 
          } 
        }], 
        "obj": "java.lang:name=Copy,type=GarbageCollector", 
        "resultAlias": "nimbus", 
        "attr": [ 
          "CollectionCount", 
          "CollectionTime" 
        ] 
      }, 
      { 
        "outputWriters": [{ 
          "@class": 
          "com.googlecode.jmxtrans.model.output.GangliaWriter", 
          "settings": { 
            "groupName": "nimbus", 
            "host": "IP_OF_GANGLIA_GMOND_SERVER", 
            "port": "8649" 
          } 
        }], 
        "obj": "java.lang:name=Code Cache,type=MemoryPool", 
        "resultAlias": "nimbus", 
        "attr": [ 
          "CollectionUsageThreshold", 
          "CollectionUsageThresholdCount", 
          "UsageThreshold", 
          "UsageThresholdCount" 
        ] 
      }, 
      { 
        "outputWriters": [{ 
          "@class": 
          "com.googlecode.jmxtrans.model.output.GangliaWriter", "settings": {    
           "groupName": "nimbus", 
            "host": "IP_OF_GANGLIA_GMOND_SERVER", 
            "port": "8649" 
          } 
        }], 
        "obj": "java.lang:type=Runtime",
        "resultAlias": "nimbus", 
        "attr": [ 
          "StartTime", 
          "Uptime" 
        ] 
      }
    ] 
    "numQueryThreads" : 2 
  } ] 
} 
```

这里，`12345`是`storm.yaml`文件中指定的 Nimbus 机器的 JMX 端口。

您需要将`IP_OF_NIMBUS_MACHINE`的值替换为 Nimbus 机器的 IP 地址。

您需要将`IP_OF_GANGLIA_GMOND_SERVER`的值替换为 Ganglia Gmond 服务器的 IP 地址。

1.  在每个 Storm 节点上运行以下命令以启动 JMXTrans 进程：

```scala
cd /usr/share/jmxtrans/ sudo ./jmxtrans.sh start PATH_OF_JSON_FILES
```

这里，`PATH_OF_JSON_FILE`是`supervisor.json`和`nimbus.json`文件的位置。

1.  现在，转到`http://127.0.0.1/ganglia`上的 Ganglia 页面，查看 Storm 指标。以下截图显示了 Storm 指标的样子：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00048.jpeg)

执行以下步骤来查看 Ganglia UI 上的 Storm Nimbus 和 supervisor 进程的指标：

1.  打开 Ganglia 页面。

1.  现在点击`stormcluster`链接，查看 Storm 集群的指标。

以下截图显示了 Storm supervisor 节点的指标：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00049.jpeg)

以下截图显示了 Storm Nimbus 节点的指标：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00050.jpeg)

# 总结

在本章中，我们通过 Nimbus thrift 客户端监控了 Storm 集群，类似于我们通过 Storm UI 所做的。我们还介绍了如何配置 Storm 来发布 JMX 指标以及 Storm 与 Ganglia 的集成。

在下一章中，我们将介绍 Storm 与 Kafka 的集成，并查看一些示例来说明这个过程。


# 第八章：Storm 和 Kafka 的集成

Apache Kafka 是一个高吞吐量、分布式、容错和复制的消息系统，最初在 LinkedIn 开发。Kafka 的用例从日志聚合到流处理再到替代其他消息系统都有。

Kafka 已经成为实时处理流水线中与 Storm 组合使用的重要组件之一。Kafka 可以作为需要由 Storm 处理的消息的缓冲区或者提供者。Kafka 也可以作为 Storm 拓扑发出的结果的输出接收端。

在本章中，我们将涵盖以下主题：

+   Kafka 架构——broker、producer 和 consumer

+   Kafka 集群的安装

+   在 Kafka 之间共享 producer 和 consumer

+   使用 Kafka consumer 作为 Storm spout 开发 Storm 拓扑

+   Kafka 和 Storm 集成拓扑的部署

# Kafka 简介

本节中，我们将介绍 Kafka 的架构——broker、consumer 和 producer。

# Kafka 架构

Kafka 具有与其他消息系统显著不同的架构。Kafka 是一个点对点系统（集群中的每个节点具有相同的角色），每个节点称为**broker**。broker 通过 ZooKeeper 集合协调它们的操作。ZooKeeper 集合管理的 Kafka 元数据在*在 Storm 和 Kafka 之间共享 ZooKeeper*部分中提到。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00051.gif)

图 8.1：Kafka 集群

以下是 Kafka 的重要组件：

# Producer

生产者是使用 Kafka 客户端 API 将消息发布到 Kafka 集群的实体。在 Kafka broker 中，消息由生产者实体发布到名为**topics**的实体。主题是一个持久队列（存储在主题中的数据被持久化到磁盘）。

为了并行处理，Kafka 主题可以有多个分区。每个分区的数据都以不同的文件表示。同一个主题的两个分区可以分配到不同的 broker 上，从而增加吞吐量，因为所有分区都是相互独立的。每个分区中的消息都有一个与之关联的唯一序列号，称为**offset**：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00052.jpeg)

图 8.2：Kafka 主题分布

# 复制

Kafka 支持主题分区的复制以支持容错。Kafka 自动处理分区的复制，并确保分区的副本将分配给不同的 broker。Kafka 选举一个 broker 作为分区的 leader，并且所有写入和读取都必须到分区 leader。复制功能是在 Kafka 8.0.0 版本中引入的。

Kafka 集群通过 ZooKeeper 管理**in sync replica**（ISR）的列表——与分区 leader 同步的副本。如果分区 leader 宕机，那么在 ISR 列表中存在的跟随者/副本才有资格成为失败分区的下一个 leader。

# Consumer

消费者从 broker 中读取一系列消息。每个消费者都有一个分配的 group ID。具有相同 group ID 的所有消费者作为单个逻辑消费者。主题的每条消息都会传递给具有相同 group ID 的消费者组中的一个消费者。特定主题的不同消费者组可以以自己的速度处理消息，因为消息在被消费后并不会立即从主题中移除。事实上，消费者有责任跟踪他们已经消费了多少消息。

如前所述，每个分区中的每条消息都有一个与之关联的唯一序列号，称为 offset。通过这个 offset，消费者知道他们已经处理了多少流。如果消费者决定重新播放已经处理过的消息，他只需要将 offset 的值设置为之前的值，然后再从 Kafka 中消费消息。

# Broker

经纪人从生产者（推送机制）接收消息，并将消息传递给消费者（拉取机制）。经纪人还管理文件中消息的持久性。Kafka 经纪人非常轻量级：它们只在队列（主题分区）上打开文件指针，并管理 TCP 连接。

# 数据保留

Kafka 中的每个主题都有一个关联的保留时间。当此时间到期时，Kafka 会删除该特定主题的过期数据文件。这是一个非常高效的操作，因为它是一个文件删除操作。

# 安装 Kafka 经纪人

在撰写本文时，Kafka 的稳定版本是 0.9.x。

运行 Kafka 的先决条件是 ZooKeeper 集合和 Java 版本 1.7 或更高版本。Kafka 附带了一个方便的脚本，可以启动单节点 ZooKeeper，但不建议在生产环境中使用。我们将使用我们在第二章中部署的 ZooKeeper 集群。

我们将首先看如何设置单节点 Kafka 集群，然后再看如何添加另外两个节点以运行一个完整的、启用了复制的三节点 Kafka 集群。

# 设置单节点 Kafka 集群

以下是设置单节点 Kafka 集群的步骤：

1.  从[`apache.claz.org/kafka/0.9.0.1/kafka_2.10-0.9.0.1.tgz`](http://apache.claz.org/kafka/0.9.0.1/kafka_2.10-0.9.0.1.tgz)下载 Kafka 0.9.x 二进制分发版，文件名为`kafka_2.10-0.9.0.1.tar.gz`。

1.  使用以下命令将存档文件提取到您想要安装 Kafka 的位置：

```scala
tar -xvzf kafka_2.10-0.9.0.1.tgz
cd kafka_2.10-0.9.0.1  
```

从现在开始，我们将把 Kafka 安装目录称为`$KAFKA_HOME`。

1.  更改`$KAFKA_HOME/config/server.properties`文件中的以下属性：

```scala
log.dirs=/var/kafka-logszookeeper.connect=zoo1:2181,zoo2:2181,zoo3:2181
```

在这里，`zoo1`、`zoo2`和`zoo3`代表了 ZooKeeper 节点的主机名。

以下是`server.properties`文件中重要属性的定义：

+   +   `broker.id`：这是 Kafka 集群中每个经纪人的唯一整数 ID。

+   `port`：这是 Kafka 经纪人的端口号。默认值为`9092`。如果您想在单台机器上运行多个经纪人，请为每个经纪人指定一个唯一的端口。

+   `host.name`：代表经纪人应该绑定和宣传自己的主机名。

+   `log.dirs`：这个属性的名称有点不幸，因为它代表的不是 Kafka 的日志目录，而是 Kafka 存储实际发送到它的数据的目录。它可以接受单个目录或逗号分隔的目录列表来存储数据。通过将多个物理磁盘连接到经纪人节点并指定多个数据目录，每个目录位于不同的磁盘上，可以增加 Kafka 的吞吐量。在同一物理磁盘上指定多个目录并没有太大用处，因为所有 I/O 仍然会在同一磁盘上进行。

+   `num.partitions`：这代表了新创建主题的默认分区数。在创建新主题时，可以覆盖此属性。分区数越多，可以实现更大的并行性，但会增加文件数量。

+   `log.retention.hours`：Kafka 在消费者消费消息后不会立即删除消息。它会保留消息一定小时数，由此属性定义，以便在出现任何问题时，消费者可以从 Kafka 重放消息。默认值为`168`小时，即 1 周。

+   `zookeeper.connect`：这是以`hostname:port`形式的 ZooKeeper 节点的逗号分隔列表。

1.  通过运行以下命令启动 Kafka 服务器：

```scala

> ./bin/kafka-server-start.sh config/server.properties 

[2017-04-23 17:44:36,667] INFO New leader is 0 (kafka.server.ZookeeperLeaderElector$LeaderChangeListener)
[2017-04-23 17:44:36,668] INFO Kafka version : 0.9.0.1 (org.apache.kafka.common.utils.AppInfoParser)
[2017-04-23 17:44:36,668] INFO Kafka commitId : a7a17cdec9eaa6c5 (org.apache.kafka.common.utils.AppInfoParser)
[2017-04-23 17:44:36,670] INFO [Kafka Server 0], started (kafka.server.KafkaServer)  
```

如果您在控制台上得到类似于前三行的内容，那么您的 Kafka 经纪人已经启动，我们可以继续测试。

1.  现在我们将通过发送和接收一些测试消息来验证 Kafka 经纪人是否设置正确。首先，让我们通过执行以下命令为测试创建一个验证主题：

```scala

> bin/kafka-topics.sh --zookeeper zoo1:2181 --replication-factor 1 --partition 1 --topic verification-topic --create

Created topic "verification-topic".  
```

1.  现在让我们通过列出所有主题来验证主题创建是否成功：

```scala

> bin/kafka-topics.sh --zookeeper zoo1:2181 --list

verification-topic  
```

1.  主题已创建；让我们为 Kafka 集群生成一些示例消息。Kafka 附带了一个命令行生产者，我们可以用来生成消息：

```scala

> bin/kafka-console-producer.sh --broker-list localhost:9092 --topic verification-topic    

```

1.  在控制台上写入以下消息：

```scala
Message 1
Test Message 2
Message 3  
```

1.  让我们通过在新的控制台窗口上启动新的控制台消费者来消费这些消息：

```scala
> bin/kafka-console-consumer.sh --zookeeper localhost:2181 --topic verification-topic --from-beginning

Message 1
Test Message 2
Message 3  
```

现在，如果我们在生产者控制台上输入任何消息，它将自动被此消费者消费并显示在命令行上。

**使用 Kafka 的单节点 ZooKeeper** 如果您不想使用外部 ZooKeeper 集合，可以使用 Kafka 附带的单节点 ZooKeeper 实例进行快速开发。要开始使用它，首先修改`$KAFKA_HOME/config/zookeeper.properties`文件以指定数据目录，提供以下属性：

`dataDir=/var/zookeeper`

现在，您可以使用以下命令启动 Zookeeper 实例：

`> ./bin/zookeeper-server-start.sh config/zookeeper.properties`

# 设置三节点 Kafka 集群

到目前为止，我们有一个单节点 Kafka 集群。按照以下步骤部署 Kafka 集群：

1.  创建一个三节点 VM 或三台物理机。

1.  执行*设置单节点 Kafka 集群*部分中提到的步骤 1 和 2。

1.  更改文件`$KAFKA_HOME/config/server.properties`中的以下属性：

```scala
broker.id=0
port=9092
host.name=kafka1
log.dirs=/var/kafka-logs
zookeeper.connect=zoo1:2181,zoo2:2181,zoo3:2181
```

确保`broker.id`属性的值对于每个 Kafka 代理都是唯一的，`zookeeper.connect`的值在所有节点上必须相同。

1.  通过在所有三个框上执行以下命令来启动 Kafka 代理：

```scala
> ./bin/kafka-server-start.sh config/server.properties
```

1.  现在让我们验证设置。首先使用以下命令创建一个主题：

```scala
> bin/kafka-topics.sh --zookeeper zoo1:2181 --replication-factor 4 --partition 1 --topic verification --create

    Created topic "verification-topic".  
```

1.  现在，我们将列出主题以查看主题是否成功创建：

```scala
> bin/kafka-topics.sh --zookeeper zoo1:2181 --list

                topic: verification     partition: 0      leader: 0   replicas: 0             isr: 0
                topic: verification     partition: 1      leader: 1   replicas: 1             isr: 1
                topic: verification     partition: 2      leader: 2   replicas: 2             isr: 2  
```

1.  现在，我们将通过使用 Kafka 控制台生产者和消费者来验证设置，就像在*设置单节点 Kafka 集群*部分中所做的那样：

```scala
> bin/kafka-console-producer.sh --broker-list kafka1:9092,kafka2:9092,kafka3:9092 --topic verification  
```

1.  在控制台上写入以下消息：

```scala
First
Second
Third  
```

1.  让我们通过在新的控制台窗口上启动新的控制台消费者来消费这些消息：

```scala
> bin/kafka-console-consumer.sh --zookeeper localhost:2181 --topic verification --from-beginning

First
Second
Third 
```

到目前为止，我们有三个在工作的 Kafka 集群代理。在下一节中，我们将看到如何编写一个可以向 Kafka 发送消息的生产者：

# 单个节点上的多个 Kafka 代理

如果您想在单个节点上运行多个 Kafka 代理，则请按照以下步骤进行操作：

1.  复制`config/server.properties`以创建`config/server1.properties`和`config/server2.properties`。

1.  在`config/server.properties`中填写以下属性：

```scala
broker.id=0 
port=9092 
log.dirs=/var/kafka-logs 
zookeeper.connect=zoo1:2181,zoo2:2181,zoo3:2181 
```

1.  在`config/server1.properties`中填写以下属性：

```scala
broker.id=1 
port=9093 
log.dirs=/var/kafka-1-logs 
zookeeper.connect=zoo1:2181,zoo2:2181,zoo3:2181 
```

1.  在`config/server2.properties`中填写以下属性：

```scala
broker.id=2 
port=9094 
log.dirs=/var/kafka-2-logs 
zookeeper.connect=zoo1:2181,zoo2:2181,zoo3:2181 
```

1.  在三个不同的终端上运行以下命令以启动 Kafka 代理：

```scala
> ./bin/kafka-server-start.sh config/server.properties
> ./bin/kafka-server-start.sh config/server1.properties
> ./bin/kafka-server-start.sh config/server2.properties

```

# 在 Storm 和 Kafka 之间共享 ZooKeeper

我们可以在 Kafka 和 Storm 之间共享相同的 ZooKeeper 集合，因为两者都将元数据存储在不同的 znodes 中（ZooKeeper 使用共享的分层命名空间协调分布式进程，其组织方式类似于标准文件系统。在 ZooKeeper 中，由数据寄存器组成的命名空间称为 znodes）。

我们需要打开 ZooKeeper 客户端控制台来查看为 Kafka 和 Storm 创建的 znodes（共享命名空间）。

转到`ZK_HOME`并执行以下命令以打开 ZooKeeper 控制台：

```scala
> bin/zkCli.sh  
```

执行以下命令以查看 znodes 列表：

```scala
> [zk: localhost:2181(CONNECTED) 0] ls /

**[storm, consumers, isr_change_notification, zookeeper, admin, brokers]**
```

在这里，消费者、`isr_change_notification`和代理是 znodes，Kafka 正在将其元数据信息管理到 ZooKeeper 的此位置。

Storm 在 ZooKeeper 中的 Storm znodes 中管理其元数据。

# Kafka 生产者并将数据发布到 Kafka

在本节中，我们正在编写一个 Kafka 生产者，它将发布事件到 Kafka 主题中。

执行以下步骤创建生产者：

1.  使用`com.stormadvance`作为`groupId`和`kafka-producer`作为`artifactId`创建一个 Maven 项目。

1.  在`pom.xml`文件中为 Kafka 添加以下依赖项：

```scala
<dependency> 
  <groupId>org.apache.kafka</groupId> 
  <artifactId>kafka_2.10</artifactId> 
  <version>0.9.0.1</version> 
  <exclusions> 
    <exclusion> 
      <groupId>com.sun.jdmk</groupId> 
      <artifactId>jmxtools</artifactId> 
    </exclusion> 
    <exclusion> 
      <groupId>com.sun.jmx</groupId> 
      <artifactId>jmxri</artifactId> 
    </exclusion> 
  </exclusions> 
</dependency> 
<dependency> 
  <groupId>org.apache.logging.log4j</groupId> 
  <artifactId>log4j-slf4j-impl</artifactId> 
  <version>2.0-beta9</version> 
</dependency> 
<dependency> 
  <groupId>org.apache.logging.log4j</groupId> 
  <artifactId>log4j-1.2-api</artifactId> 
  <version>2.0-beta9</version> 
</dependency>  
```

1.  在`pom.xml`文件中添加以下`build`插件。这将允许我们使用 Maven 执行生产者：

```scala
<build> 
  <plugins> 
    <plugin> 
      <groupId>org.codehaus.mojo</groupId> 
      <artifactId>exec-maven-plugin</artifactId> 
      <version>1.2.1</version> 
      <executions> 
        <execution> 
          <goals> 
            <goal>exec</goal> 
          </goals> 
        </execution> 
      </executions> 
      <configuration> 
        <executable>java</executable
        <includeProjectDependencies>true</includeProjectDependencies
        <includePluginDependencies>false</includePluginDependencies> 
        <classpathScope>compile</classpathScope> 
        <mainClass>com.stormadvance.kafka_producer. KafkaSampleProducer 
        </mainClass> 
      </configuration> 
    </plugin> 
  </plugins> 
</build> 
```

1.  现在我们将在`com.stormadvance.kafka_producer`包中创建`KafkaSampleProducer`类。该类将从弗朗茨·卡夫卡的《变形记》第一段中的每个单词产生单词，并将其作为单个消息发布到 Kafka 的`new_topic`主题中。以下是`KafkaSampleProducer`类的代码及解释：

```scala
public class KafkaSampleProducer { 
  public static void main(String[] args) { 
    // Build the configuration required for connecting to Kafka 
    Properties props = new Properties(); 

    // List of kafka borkers. Complete list of brokers is not required as 
    // the producer will auto discover the rest of the brokers. 
    props.put("bootstrap.servers", "Broker1-IP:9092"); 
    props.put("batch.size", 1); 
    // Serializer used for sending data to kafka. Since we are sending string, 
    // we are using StringSerializer. 
    props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer"); 
    props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer"); 

    props.put("producer.type", "sync"); 

    // Create the producer instance 
    Producer<String, String> producer = new KafkaProducer<String, String>(props); 

    // Now we break each word from the paragraph 
    for (String word : METAMORPHOSIS_OPENING_PARA.split("\\s")) { 
      System.out.println("word : " + word); 
      // Create message to be sent to "new_topic" topic with the word 
      ProducerRecord<String, String> data = new ProducerRecord<String, String>("new_topic",word, word); 
      // Send the message 
      producer.send(data); 
    } 

    // close the producer 
    producer.close(); 
    System.out.println("end : "); 
  } 

  // First paragraph from Franz Kafka's Metamorphosis 
  private static String METAMORPHOSIS_OPENING_PARA = "One morning, when Gregor Samsa woke from troubled dreams, he found " 
               + "himself transformed in his bed into a horrible vermin.  He lay on " 
               + "his armour-like back, and if he lifted his head a little he could " 
               + "see his brown belly, slightly domed and divided by arches into stiff " 
               + "sections.  The bedding was hardly able to cover it and seemed ready " 
               + "to slide off any moment.  His many legs, pitifully thin compared " 
               + "with the size of the rest of him, waved about helplessly as he " 
               + "looked."; 

}  
```

1.  现在，在运行生产者之前，我们需要在 Kafka 中创建`new_topic`。为此，请执行以下命令：

```scala

> bin/kafka-topics.sh --zookeeper ZK1:2181 --replication-factor 1 --partition 1 --topic new_topic --create 

Created topic "new_topic1".    

```

1.  现在我们可以通过执行以下命令运行生产者：

```scala
> mvn compile exec:java
......
103  [com.learningstorm.kafka.WordsProducer.main()] INFO                kafka.client.ClientUti
ls$  - Fetching metadata from broker                                    id:0,host:kafka1,port:9092 with correlation id 0 for 1                  topic(s) Set(words_topic)
110  [com.learningstorm.kafka.WordsProducer.main()] INFO                kafka.producer.SyncProducer  - Connected to kafka1:9092 for             producing
140  [com.learningstorm.kafka.WordsProducer.main()] INFO                kafka.producer.SyncProducer  - Disconnecting from                       kafka1:9092
177  [com.learningstorm.kafka.WordsProducer.main()] INFO                kafka.producer.SyncProducer  - Connected to kafka1:9092 for             producing
378  [com.learningstorm.kafka.WordsProducer.main()] INFO                kafka.producer.Producer  - Shutting down producer
378  [com.learningstorm.kafka.WordsProducer.main()] INFO                kafka.producer.ProducerPool  - Closing all sync producers
381  [com.learningstorm.kafka.WordsProducer.main()] INFO                kafka.producer.SyncProducer  - Disconnecting from                       kafka1:9092
```

1.  现在让我们通过使用 Kafka 的控制台消费者来验证消息是否已被生产，并执行以下命令：

```scala
> bin/kafka-console-consumer.sh --zookeeper ZK:2181 --topic verification --from-beginning

                One
                morning,
                when
                Gregor
                Samsa
                woke
                from
                troubled
                dreams,
                he
                found
                himself
                transformed
                in
                his
                bed
                into
                a
                horrible
                vermin.
                ......
```

因此，我们能够向 Kafka 生产消息。在下一节中，我们将看到如何使用`KafkaSpout`从 Kafka 中读取消息并在 Storm 拓扑中处理它们。

# Kafka Storm 集成

现在我们将创建一个 Storm 拓扑，该拓扑将从 Kafka 主题`new_topic`中消费消息并将单词聚合成句子。

完整的消息流如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/ms-storm/img/00053.gif)

我们已经看到了`KafkaSampleProducer`，它将单词生产到 Kafka 代理中。现在我们将创建一个 Storm 拓扑，该拓扑将从 Kafka 中读取这些单词并将它们聚合成句子。为此，我们的应用程序中将有一个`KafkaSpout`，它将从 Kafka 中读取消息，并且有两个 bolt，`WordBolt`从`KafkaSpout`接收单词，然后将它们聚合成句子，然后传递给`SentenceBolt`，它只是在输出流上打印它们。我们将在本地模式下运行此拓扑。

按照以下步骤创建 Storm 拓扑：

1.  创建一个新的 Maven 项目，`groupId`为`com.stormadvance`，`artifactId`为`kafka-storm-topology`。

1.  在`pom.xml`文件中添加以下 Kafka-Storm 和 Storm 的依赖项：

```scala
<dependency> 
  <groupId>org.apache.storm</groupId> 
  <artifactId>storm-kafka</artifactId> 
  <version>1.0.2</version> 
  <exclusions> 
    <exclusion> 
      <groupId>org.apache.kafka</groupId> 
      <artifactId>kafka-clients</artifactId> 
    </exclusion> 
  </exclusions> 
</dependency> 

<dependency> 
  <groupId>org.apache.kafka</groupId> 
  <artifactId>kafka_2.10</artifactId> 
  <version>0.9.0.1</version> 
  <exclusions> 
    <exclusion> 
      <groupId>com.sun.jdmk</groupId> 
      <artifactId>jmxtools</artifactId> 
    </exclusion> 
    <exclusion> 
      <groupId>com.sun.jmx</groupId> 
      <artifactId>jmxri</artifactId> 
    </exclusion> 
  </exclusions> 
</dependency> 

<dependency> 
  <groupId>org.apache.storm</groupId> 
  <artifactId>storm-core</artifactId> 
  <version>1.0.2</version> 
  <scope>provided</scope> 
</dependency> 
<dependency> 
  <groupId>commons-collections</groupId> 
  <artifactId>commons-collections</artifactId> 
  <version>3.2.1</version> 
</dependency> 

<dependency> 
  <groupId>com.google.guava</groupId> 
  <artifactId>guava</artifactId> 
  <version>15.0</version> 
</dependency>  
```

1.  在`pom.xml`文件中添加以下 Maven 插件，以便我们能够从命令行运行它，并且还能够打包拓扑以在 Storm 中执行：

```scala
<build> 
  <plugins> 
    <plugin> 
      <artifactId>maven-assembly-plugin</artifactId> 
      <configuration> 
        <descriptorRefs> 
          descriptorRef>jar-with-dependencies</descriptorRef> 
        </descriptorRefs> 
        <archive> 
          <manifest> 
            <mainClass></mainClass> 
          </manifest> 
        </archive> 
      </configuration> 
      <executions> 
        <execution> 
          <id>make-assembly</id> 
          <phase>package</phase> 
          <goals> 
            <goal>single</goal> 
          </goals> 
        </execution> 
      </executions> 
    </plugin> 

    <plugin> 
      <groupId>org.codehaus.mojo</groupId> 
      <artifactId>exec-maven-plugin</artifactId> 
      <version>1.2.1</version> 
      <executions> 
        <execution> 
          <goals> 
            <goal>exec</goal> 
          </goals> 
        </execution> 
      </executions> 
      <configuration> 
        <executable>java</executable
        <includeProjectDependencies>true</includeProjectDependencies
        <includePluginDependencies>false</includePluginDependencies> 
        <classpathScope>compile</classpathScope> 
        <mainClass>${main.class}</mainClass> 
      </configuration> 
    </plugin> 

    <plugin> 
      <groupId>org.apache.maven.plugins</groupId> 
      <artifactId>maven-compiler-plugin</artifactId> 
    </plugin> 

  </plugins> 
</build> 
```

1.  现在我们将首先创建`WordBolt`，它将单词聚合成句子。为此，在`com.stormadvance.kafka`包中创建一个名为`WordBolt`的类。`WordBolt`的代码如下，附有解释：

```scala
public class WordBolt extends BaseBasicBolt { 

  private static final long serialVersionUID = -5353547217135922477L; 

  // list used for aggregating the words 
  private List<String> words = new ArrayList<String>(); 

  public void execute(Tuple input, BasicOutputCollector collector) { 
    System.out.println("called"); 
    // Get the word from the tuple 
    String word = input.getString(0); 

    if (StringUtils.isBlank(word)) { 
      // ignore blank lines 
      return; 
    } 

    System.out.println("Received Word:" + word); 

    // add word to current list of words 
    words.add(word); 

    if (word.endsWith(".")) { 
      // word ends with '.' which means this is // the end of the sentence 
      // publish a sentence tuple 
      collector.emit(ImmutableList.of((Object) StringUtils.join(words, ' '))); 

      // reset the words list. 
      words.clear(); 
    } 
  } 

  public void declareOutputFields(OutputFieldsDeclarer declarer) { 
    // here we declare we will be emitting tuples with 
    // a single field called "sentence" 
    declarer.declare(new Fields("sentence")); 
  } 
} 
```

1.  接下来是`SentenceBolt`，它只是打印接收到的句子。在`com.stormadvance.kafka`包中创建`SentenceBolt`。代码如下，附有解释：

```scala
public class SentenceBolt extends BaseBasicBolt { 

  private static final long serialVersionUID = 7104400131657100876L; 

  public void execute(Tuple input, BasicOutputCollector collector) { 
    // get the sentence from the tuple and print it 
    System.out.println("Recieved Sentence:"); 
    String sentence = input.getString(0); 
    System.out.println("Recieved Sentence:" + sentence); 
  } 

  public void declareOutputFields(OutputFieldsDeclarer declarer) { 
         // we don't emit anything 
  } 
} 
```

1.  现在我们将创建`KafkaTopology`，它将定义`KafkaSpout`并将其与`WordBolt`和`SentenceBolt`连接起来。在`com.stormadvance.kafka`包中创建一个名为`KafkaTopology`的新类。代码如下，附有解释：

```scala
public class KafkaTopology { 
  public static void main(String[] args) { 
    try { 
      // ZooKeeper hosts for the Kafka cluster 
      BrokerHosts zkHosts = new ZkHosts("ZKIP:PORT"); 

      // Create the KafkaSpout configuartion 
      // Second argument is the topic name 
      // Third argument is the zookeepr root for Kafka 
      // Fourth argument is consumer group id 
      SpoutConfig kafkaConfig = new SpoutConfig(zkHosts, "new_topic", "", "id1"); 

      // Specify that the kafka messages are String 
      // We want to consume all the first messages in the topic everytime 
      // we run the topology to help in debugging. In production, this 
      // property should be false 
      kafkaConfig.scheme = new SchemeAsMultiScheme(new StringScheme()); 
      kafkaConfig.startOffsetTime = kafka.api.OffsetRequest.EarliestTime(); 

      // Now we create the topology 
      TopologyBuilder builder = new TopologyBuilder(); 

      // set the kafka spout class 
      builder.setSpout("KafkaSpout", new KafkaSpout(kafkaConfig), 2); 

      // set the word and sentence bolt class 
      builder.setBolt("WordBolt", new WordBolt(), 1).globalGrouping("KafkaSpout"); 
      builder.setBolt("SentenceBolt", new SentenceBolt(), 1).globalGrouping("WordBolt"); 

      // create an instance of LocalCluster class for executing topology 
      // in local mode. 
      LocalCluster cluster = new LocalCluster(); 
      Config conf = new Config(); 
      conf.setDebug(true); 
      if (args.length > 0) { 
        conf.setNumWorkers(2); 
        conf.setMaxSpoutPending(5000); 
        StormSubmitter.submitTopology("KafkaToplogy1", conf, builder.createTopology()); 

      } else { 
        // Submit topology for execution 
        cluster.submitTopology("KafkaToplogy1", conf, builder.createTopology()); 
        System.out.println("called1"); 
        Thread.sleep(1000000); 
        // Wait for sometime before exiting 
        System.out.println("Waiting to consume from kafka"); 

        System.out.println("called2"); 
        // kill the KafkaTopology 
        cluster.killTopology("KafkaToplogy1"); 
        System.out.println("called3"); 
        // shutdown the storm test cluster 
        cluster.shutdown(); 
      } 

    } catch (Exception exception) { 
      System.out.println("Thread interrupted exception : " + exception); 
    } 
  } 
} 
```

1.  现在我们将运行拓扑。确保 Kafka 集群正在运行，并且您已经在上一节中执行了生产者，以便 Kafka 中有消息可以消费。

1.  通过执行以下命令运行拓扑：

```scala
> mvn clean compile exec:java  -Dmain.class=com.stormadvance.kafka.KafkaTopology 
```

这将执行拓扑。您应该在输出中看到类似以下的消息：

```scala
Recieved Word:One
Recieved Word:morning,
Recieved Word:when
Recieved Word:Gregor
Recieved Word:Samsa
Recieved Word:woke
Recieved Word:from
Recieved Word:troubled
Recieved Word:dreams,
Recieved Word:he
Recieved Word:found
Recieved Word:himself
Recieved Word:transformed
Recieved Word:in
Recieved Word:his
Recieved Word:bed
Recieved Word:into
Recieved Word:a
Recieved Word:horrible
Recieved Word:vermin.
Recieved Sentence:One morning, when Gregor Samsa woke from              troubled dreams, he found himself transformed in his bed                   into a horrible vermin.  
```

因此，我们能够从 Kafka 中消费消息并在 Storm 拓扑中处理它们。

# 在 Storm 集成拓扑中部署 Kafka

在 Storm 集群上部署 Kafka 和 Storm 集成拓扑与部署其他拓扑类似。我们需要设置工作程序的数量和最大的 spout pending Storm 配置，并且我们需要使用`StormSubmitter`的`submitTopology`方法将拓扑提交到 Storm 集群上。

现在，我们需要按照以下步骤构建拓扑代码，以创建 Kafka Storm 集成拓扑的 JAR 包：

1.  转到项目主页。

1.  执行命令：

```scala
mvn clean install
```

上述命令的输出如下：

```scala
------------------------------------------------------------------ ----- [INFO] ----------------------------------------------------------- ----- [INFO] BUILD SUCCESS [INFO] ----------------------------------------------------------- ----- [INFO] Total time: 58.326s [INFO] Finished at: [INFO] Final Memory: 14M/116M [INFO] ----------------------------------------------------------- -----
```

1.  现在，将 Kafka Storm 拓扑复制到 Nimbus 机器上，并执行以下命令将拓扑提交到 Storm 集群上：

```scala
bin/storm jar jarName.jar [TopologyMainClass] [Args]
```

前面的命令运行`TopologyMainClass`并带有参数。`TopologyMainClass`的主要功能是定义拓扑并将其提交到 Nimbus。Storm JAR 部分负责连接到 Nimbus 并上传 JAR 部分。

1.  登录 Storm Nimbus 机器并执行以下命令：

```scala
$> cd $STORM_HOME
$> bin/storm jar ~/storm-kafka-topology-0.0.1-SNAPSHOT-jar-with-dependencies.jar com.stormadvance.kafka.KafkaTopology KafkaTopology1
```

在这里，`~/ storm-kafka-topology-0.0.1-SNAPSHOT-jar-with-dependencies.jar`是我们在 Storm 集群上部署的`KafkaTopology` JAR 的路径。

# 总结

在本章中，我们学习了 Apache Kafka 的基础知识以及如何将其作为与 Storm 一起构建实时流处理管道的一部分。我们了解了 Apache Kafka 的架构以及如何通过使用`KafkaSpout`将其集成到 Storm 处理中。

在下一章中，我们将介绍 Storm 与 Hadoop 和 YARN 的集成。我们还将介绍此操作的示例示例。
