# Docker AWS 教程（五）

> 原文：[`zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5`](https://zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：隔离网络访问

应用安全的基本组件是控制网络访问的能力，无论是应用内部还是应用外部。AWS 提供了 EC2 安全组，可以在每个网络接口上应用到您的 EC2 实例。这种机制对于部署到 EC2 实例的传统应用程序非常有效，但对于容器应用程序来说效果不佳，因为它们通常在共享的 EC2 实例上运行，并通过 EC2 实例上的共享主机接口进行通信。对于 ECS 来说，直到最近的方法是为您需要支持在给定 ECS 容器实例上运行的所有容器的网络安全需求应用两个安全组，这降低了安全规则的有效性，对于具有高安全要求的应用程序来说是不可接受的。直到最近，这种方法的唯一替代方案是为每个应用程序构建专用的 ECS 集群，以确保满足应用程序的安全要求，但这会增加额外的基础设施和运营开销。

AWS 在 2017 年底宣布了一项名为 ECS 任务网络的功能，引入了动态分配弹性网络接口（ENI）给您的 ECS 容器实例的能力，这个 ENI 专门用于给定的 ECS 任务。这使您能够为每个容器应用程序创建特定的安全组，并在同一 ECS 容器实例上同时运行这些应用程序，而不会影响安全性。

在本章中，您将学习如何配置 ECS 任务网络，这需要您了解 ECS 任务网络的工作原理，为任务网络配置 ECS 任务定义，并创建部署与您的任务网络启用的 ECS 任务定义相关联的 ECS 服务。与您在上一章中配置的 ECS 任务角色功能相结合，这将使您能够构建高度安全的容器应用程序环境，以在 IAM 权限和网络安全级别上执行隔离和分离。

将涵盖以下主题：

+   理解 ECS 任务网络

+   配置 NAT 网关

+   配置 ECS 任务网络

+   部署和测试 ECS 任务网络

# 技术要求

以下列出了完成本章所需的技术要求：

+   对 AWS 账户的管理员访问

+   根据第三章的说明配置本地 AWS 配置文件

+   AWS CLI 1.15.71 或更高版本

+   完成第九章，并成功将示例应用程序部署到 AWS

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch10`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch10)。

观看以下视频以查看代码的实际操作：

[`bit.ly/2MUBJfs`](http://bit.ly/2MUBJfs)

# 理解 ECS 任务网络

在幕后，ECS 任务网络实际上是一个相当复杂的功能，它依赖于许多 Docker 网络功能，并需要对 Docker 网络有详细的了解。作为在 AWS 中使用 ECS 设计、构建和部署容器环境的人，好消息是你不必理解这个细节层次，你只需要对 ECS 任务网络如何工作有一个高层次的理解。因此，在本节中，我将提供 ECS 任务网络如何工作的高层次概述，但是，如果你对 ECS 任务网络如何工作感兴趣，这篇来自 AWS 的博客文章提供了更多信息([`aws.amazon.com/blogs/compute/under-the-hood-task-networking-for-amazon-ecs/`](https://aws.amazon.com/blogs/compute/under-the-hood-task-networking-for-amazon-ecs/))。

# Docker 桥接网络

要理解 ECS 任务网络，有助于了解 Docker 网络和 ECS 容器的标准配置是如何默认工作的。默认情况下，ECS 任务定义配置为 Docker 桥接网络模式，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/64cd1234-38fd-40fb-9d7b-c30700f382ea.png)Docker 桥接网络

在上图中，您可以看到每个 ECS 任务都有自己的专用网络接口，这是由 Docker 引擎在创建 ECS 任务容器时动态创建的。Docker 桥接接口是一个类似于以太网交换机的第 2 层网络组件，它在 Docker 引擎主机内部连接每个 Docker 容器网络接口。

请注意，每个容器都有一个 IP 地址，位于`172.16.0.x`子网内，而 ECS 容器实例的外部 AWS 公共网络和弹性网络接口的 IP 地址位于`172.31.0.x`子网内，您可以看到所有容器流量都通过单个主机网络接口路由，在 AWS EC2 实例的情况下，这是分配给实例的默认弹性网络接口。弹性网络接口（ENI）是一种 EC2 资源，为您的 VPC 子网提供网络连接，并且是您认为每个 EC2 实例使用的标准网络接口。

ECS 代理也作为一个 Docker 容器运行，与其他容器不同的是它以主机网络模式运行，这意味着它使用主机操作系统的网络接口（即 ENI）进行网络通信。因为容器位于内部对 Docker 引擎主机的不同 IP 网络上，为了与外部世界建立网络连接，Docker 在 ENI 上配置了 iptables 规则，将所有出站网络流量转换为弹性网络接口的 IP 地址，并为入站网络流量设置动态端口映射规则。例如，前面图表中一个容器的动态端口映射规则会将`172.31.0.99:32768`的传入流量转换为`172.16.0.101:8000`。

iptables 是标准的 Linux 内核功能，为您的 Linux 主机提供网络访问控制和网络地址转换功能。

尽管许多应用程序使用网络地址转换（NAT）运行良好，但有些应用程序对 NAT 的支持不佳，甚至根本无法支持，并且对于网络流量较大的应用程序，使用 NAT 可能会影响性能。还要注意，应用于 ENI 的安全组是所有容器、ECS 代理和操作系统本身共享的，这意味着安全组必须允许所有这些组件的组合网络连接要求，这可能会危及您的容器和 ECS 容器实例的安全。

可以配置 ECS 任务定义以在主机网络模式下运行，这意味着它们的网络配置类似于 ECS 代理配置，不需要网络地址转换（NAT）。主机网络模式具有自己的安全性影响，通常不建议用于希望避免 NAT 或需要网络隔离的应用程序，而应该使用 ECS 任务网络来满足这些要求。主机网络应谨慎使用，仅用于执行系统功能的 ECS 任务，例如日志记录或监视辅助容器。

# ECS 任务网络

现在您对 ECS 容器实例及其关联容器的默认网络配置有了基本了解，让我们来看看当您配置 ECS 任务网络时，这个情况会如何改变。以下图表概述了 ECS 任务网络的工作原理：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/bf9feb71-45dc-4c68-9b73-e707910cb295.png)ECS 任务网络

在上图中，每个 ECS 任务都被分配和配置为使用自己专用的弹性网络接口。这与第一个图表有很大不同，其中容器使用由 Docker 动态创建的内部网络接口，而 ECS 负责动态创建每个 ECS 任务的弹性网络接口。这对 ECS 来说更加复杂，但优势在于您的容器可以直接附加到 VPC 子网，并且可以拥有自己独立的安全组。这意味着您的容器网络端口不再需要复杂的功能，如动态端口映射，这会影响安全性和性能，您的容器端口直接暴露给 AWS 网络环境，并可以直接被负载均衡器访问。

在前面的图表中需要注意的一点是外部网络配置，引入了私有子网和公共子网的概念。我以这种方式表示网络连接，因为在撰写本文时，ECS 任务网络不支持为每个动态创建的 ENI 分配公共 IP 地址，因此如果您的容器需要互联网连接，则确实需要额外的 VPC 网络设置。此设置涉及在公共网络上创建 NAT 网关或 HTTP 代理，然后您的 ECS 任务可以将互联网流量路由到该网关。在当前 todobackend 应用程序的情况下，第九章介绍的入口脚本与位于互联网上的 AWS Secrets Manager API 通信，因此需要类似于第一个图表中显示的网络设置。

ECS 代理没有无法分配公共 IP 地址的限制，因为它使用在创建时分配给实例的默认 EC2 实例 ENI。例如，在前面的图表中，您可以将 ECS 代理使用的默认 ENI 连接到公共网络或具有互联网连接的其他网络。

通过比较前面的两个图表，您可以看到 ECS 任务网络简化了 ECS 容器实例的内部网络配置，使其看起来更像是传统的虚拟机网络模型，如果您想象 ECS 容器实例是一台裸金属服务器，您的容器是虚拟机。这带来了更高的性能和安全性，但需要更复杂的外部网络设置，需要为出站互联网连接配置 NAT 网关或 HTTP 代理，并且 ECS 负责动态附加 ENI 到您的实例，这也带来了自己的限制。

例如，可以附加到给定 EC2 实例的 ENI 的最大数量取决于 EC2 实例类型，如果您查看[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI)，您会发现免费套餐 t2.micro 实例类型仅支持最多两个 ENI，这限制了您可以在 ECS 任务网络模式下运行的 ECS 任务的最大数量为每个实例只能运行一个（因为一个 ENI 始终保留给主机）。

# 配置 NAT 网关

正如您在前一节中了解到的，在撰写本文时，ECS 任务网络不支持分配公共 IP 地址，这意味着您必须配置额外的基础设施来支持应用程序可能需要的任何互联网连接。尽管应用程序可以通过堆栈中的应用程序负载均衡器进行无出站互联网访问，但应用程序容器入口脚本确实需要在启动时与 AWS Secrets Manager 服务通信，这需要与 Secrets Manager API 通信的互联网连接。

为了提供这种连接性，您可以采用两种典型的方法：

+   **配置 NAT 网关**：这是 AWS 管理的服务，为出站通信提供网络地址转换，使位于私有子网上的主机和容器能够访问互联网。

+   **配置 HTTP 代理**：这提供了一个前向代理，其中配置了代理支持的应用程序并将 HTTP、HTTPS 和 FTP 请求转发到您的代理。

我通常推荐后一种方法，因为它可以根据 DNS 命名限制对 HTTP 和 HTTPS 流量的访问（后者取决于所使用的 HTTP 代理的能力），而 NAT 网关只能根据 IP 地址限制访问。然而，设置代理确实需要更多的努力，并且需要管理额外的服务的运营开销，因此为了专注于 ECS 任务网络并保持简单，我们将在本章中实施 NAT 网关方法。

# 配置私有子网和路由表

为了支持具有典型路由配置的 NAT 网关，我们需要首先添加一个私有子网以及一个私有路由表，这些将作为 CloudFormation 资源添加到您的 todobackend 堆栈中。以下示例演示了在 todobackend-aws 存储库的根目录中的`stack.yml`文件中执行此配置：

为了保持本示例简单，我们正在创建 todobackend 应用程序堆栈中的网络资源，但通常您会在单独的网络重点 CloudFormation 堆栈中创建网络子网和相关资源，如 NAT 网关。

```
...
...
Resources:
  PrivateSubnet:
 Type: AWS::EC2::Subnet
 Properties:
 AvailabilityZone: !Sub ${AWS::Region}a
 CidrBlock: 172.31.96.0/20
 VpcId: !Ref VpcId
 PrivateRouteTable:
 Type: AWS::EC2::RouteTable
 Properties:
 VpcId: !Ref VpcId
 PrivateSubnetRouteTableAssociation:
 Type: AWS::EC2::SubnetRouteTableAssociation
 Properties:
 RouteTableId: !Ref PrivateRouteTable
 SubnetId: !Ref PrivateSubnet
...
...
```

创建私有子网和路由表

在前面的例子中，您创建了私有子网和路由表资源，然后通过`PrivateSubnetRouteTableAssociation`资源将它们关联起来。这个配置意味着从私有子网发送的所有网络流量将根据私有路由表中发布的路由进行路由。请注意，您只在本地 AWS 区域的可用区 A 中指定了一个子网—在实际情况下，您通常会为高可用性配置至少两个可用区中的两个子网。还有一点需要注意的是，您必须确保为您的子网配置的`CidrBlock`落在为您的 VPC 配置的 IP 范围内，并且没有分配给任何其他子网。

以下示例演示了使用 AWS CLI 来确定 VPC IP 范围并查看现有子网 CIDR 块：

```
> export AWS_PROFILE=docker-in-aws
> aws ec2 describe-vpcs --query Vpcs[].CidrBlock
[
    "172.31.0.0/16"
]
> aws ec2 describe-subnets --query Subnets[].CidrBlock
[
    "172.31.16.0/20",
    "172.31.80.0/20",
    "172.31.48.0/20",
    "172.31.64.0/20",
    "172.31.32.0/20",
    "172.31.0.0/20"
]
```

查询 VPC 和子网 CIDR 块

在前面的例子中，您可以看到默认的 VPC 已经配置了一个 CIDR 块`172.31.0.0/16`，您还可以看到已经分配给默认 VPC 中创建的默认子网的现有 CIDR 块。如果您回到第一个例子，您会看到我们选择了这个块中的下一个`/20`子网（`172.31.96.0/20`）用于新定义的私有子网。

# 配置 NAT 网关

在私有路由配置就绪后，您现在可以配置 NAT 网关和其他支持资源。

NAT 网关需要一个弹性 IP 地址，这是出站流量经过 NAT 网关时将显示为源自的固定公共 IP 地址，并且必须安装在具有互联网连接的公共子网上。

以下示例演示了配置 NAT 网关以及关联的弹性 IP 地址：

```
...
...
Resources:
 NatGateway:
 Type: AWS::EC2::NatGateway
 Properties:
 AllocationId: !Sub ${ElasticIP.AllocationId}
 SubnetId:
 Fn::Select:
 - 0
 - !Ref ApplicationSubnets
 ElasticIP:
 Type: AWS::EC2::EIP
 Properties:
 Domain: vpc
...
...
```

配置 NAT 网关

在前面的例子中，您创建了一个为 VPC 分配的弹性 IP 地址，然后通过`AllocationId`属性将分配的 IP 地址链接到 NAT 网关。

弹性 IP 地址在计费方面有些有趣，因为 AWS 只要您在积极使用它们，就不会向您收费。如果您创建弹性 IP 地址但没有将它们与 EC2 实例或 NAT 网关关联，那么 AWS 将向您收费。有关弹性 IP 地址计费方式的更多详细信息，请参见[`aws.amazon.com/premiumsupport/knowledge-center/elastic-ip-charges/`](https://aws.amazon.com/premiumsupport/knowledge-center/elastic-ip-charges/)。

注意在指定`SubnetId`时使用了`Fn::Select`内在函数，重要的是要理解子网必须与将链接到 NAT 网关的子网和路由表资源位于相同的可用区。在我们的用例中，这是可用区 A，`ApplicationSubnets`输入包括两个子网 ID，分别位于可用区 A 和 B，因此您选择第一个从零开始的子网 ID。请注意，您可以使用以下示例中演示的`aws ec2 describe-subnets`命令来验证子网的可用区：

```
> cat dev.cfg
ApplicationDesiredCount=1
ApplicationImageId=ami-ec957491
ApplicationImageTag=5fdbe62
ApplicationSubnets=subnet-a5d3ecee,subnet-324e246f VpcId=vpc-f8233a80
> aws ec2 describe-subnets --query Subnets[].[AvailabilityZone,SubnetId] --output table
-----------------------------------
|         DescribeSubnets         |
+-------------+-------------------+
|  us-east-1a |  subnet-a5d3ecee  |
|  us-east-1d |  subnet-c2abdded  |
|  us-east-1f |  subnet-aae11aa5  |
|  us-east-1e |  subnet-fd3a43c2  |
|  us-east-1b |  subnet-324e246f  |
|  us-east-1c |  subnet-d281a2b6  |
+-------------+-------------------+
```

按可用区查询子网 ID

在前面的示例中，您可以看到`dev.cfg`文件中`ApplicationSubnets`输入中的第一项是`us-east-1a`的子网 ID，确保 NAT 网关将安装到正确的可用区。

# 为您的私有子网配置路由

配置 NAT 网关的最后一步是为您的私有子网配置默认路由，指向您的 NAT 网关资源。此配置将确保所有出站互联网流量将被路由到您的 NAT 网关，然后执行地址转换，使您的私有主机和容器能够与互联网通信。

以下示例演示了为您之前创建的私有路由表添加默认路由：

```
...
...
Resources:
 PrivateRouteTableDefaultRoute:
 Type: AWS::EC2::Route
 Properties:
 DestinationCidrBlock: 0.0.0.0/0
 RouteTableId: !Ref PrivateRouteTable
      NatGatewayId: !Ref NatGateway
...
...
```

配置默认路由

在前面的示例中，您可以看到您配置了`RouteTableId`和`NatGatewayId`属性，以确保您在第一个示例中创建的私有路由表的默认路由设置为您在后面示例中创建的 NAT 网关。

现在您已经准备好部署您的更改，但在这之前，让我们在 todobackend-aws 存储库中创建一个名为**ecs-task-networking**的单独分支，这样您就可以在本章末尾轻松恢复您的更改：

```
> git checkout -b ecs-task-networking
M stack.yml
Switched to a new branch 'ecs-task-networking'
> git commit -a -m "Add NAT gateway resources"
[ecs-task-networking af06d37] Add NAT gateway resources
 1 file changed, 33 insertions(+)
```

创建 ECS 任务网络分支

现在，您可以使用您一直在本书中用于堆栈部署的熟悉的`aws cloudformation deploy`命令部署您的更改：

```
> export AWS_PROFILE=docker-in-aws > aws cloudformation deploy --template-file stack.yml \
 --stack-name todobackend --parameter-overrides $(cat dev.cfg) \ --capabilities CAPABILITY_NAMED_IAM Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga:

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - todobackend
> aws ec2 describe-subnets --query "Subnets[?CidrBlock=='172.31.96.0/20'].SubnetId" ["subnet-3acd6370"]
> aws ec2 describe-nat-gateways
{
    "NatGateways": [
        {
            "CreateTime": "2018-04-22T10:30:07.000Z",
            "NatGatewayAddresses": [
                {
                    "AllocationId": "eipalloc-838abd8a",
                    "NetworkInterfaceId": "eni-90d8f10c",
                    "PrivateIp": "172.31.21.144",
 "PublicIp": "18.204.39.34"
                }
            ],
            "NatGatewayId": "nat-084089330e75d23b3",
            "State": "available",
            "SubnetId": "subnet-a5d3ecee",
            "VpcId": "vpc-f8233a80",
...
...
```

部署更改到 todobackend 应用程序

在前面的示例中，成功部署 CloudFormation 更改后，您使用`aws ec2 describe-subnets`命令查询您创建的新子网的子网 ID，因为您稍后在本章中将需要这个值。您还运行`aws ec2 describe-nat-gateways`命令来验证 NAT 网关是否成功创建，并查看网关的弹性 IP 地址，该地址由突出显示的`PublicIP`属性表示。请注意，您还应检查默认路由是否正确创建，如以下示例所示：

```
> aws ec2 describe-route-tables \
 --query "RouteTables[].Routes[?DestinationCidrBlock=='0.0.0.0/0']"
[
    [
        {
            "DestinationCidrBlock": "0.0.0.0/0",
            "NatGatewayId": "nat-084089330e75d23b3",
            "Origin": "CreateRoute",
            "State": "active"
        }
    ],
    [
        {
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": "igw-1668666f",
            "Origin": "CreateRoute",
            "State": "active"
        }
    ]
]
...
...
```

检查默认路由

在前面的示例中，您可以看到存在两个默认路由，一个默认路由与 NAT 网关关联，另一个与互联网网关关联，证实您帐户中的一个路由表正在将互联网流量路由到您新创建的 NAT 网关。

# 配置 ECS 任务网络

现在，您已经建立了支持 ECS 任务网络私有 IP 寻址要求的网络基础设施，您可以继续在 ECS 资源上配置 ECS 任务网络。这需要以下配置和考虑：

+   您必须配置 ECS 任务定义和 ECS 服务以支持 ECS 任务网络。

+   任务定义的网络模式必须设置为`awsvpc`。

+   用于 ECS 任务网络的弹性网络接口只能与一个 ECS 任务关联。根据您的 ECS 实例类型，这将限制您在任何给定的 ECS 容器实例中可以运行的 ECS 任务的最大数量。

+   使用配置了 ECS 任务网络的 ECS 任务部署比传统的 ECS 部署时间更长，因为需要创建一个弹性网络接口并将其绑定到您的 ECS 容器实例。

+   由于您的容器应用程序有一个专用的网络接口，动态端口映射不再可用，您的容器端口直接暴露在网络接口上。

+   当使用`awsvpc`网络模式的 ECS 服务与应用程序负载均衡器目标组一起使用时，目标类型必须设置为`ip`（默认值为`instance`）。

动态端口映射的移除意味着，例如，todobackend 应用程序（运行在端口 8000 上）将在启用任务网络的情况下在外部使用端口`8000`访问，而不是通过动态映射的端口。这将提高生成大量网络流量的应用程序的性能，并且意味着您的安全规则可以针对应用程序运行的特定端口，而不是允许访问动态端口映射使用的临时网络端口范围。

# 为任务网络配置 ECS 任务定义

配置 ECS 任务定义以使用任务网络的第一步是配置您的 ECS 任务定义。以下示例演示了修改`ApplicationTaskDefinition`资源以支持 ECS 任务网络：

```
...
...
  ApplicationTaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: todobackend
 NetworkMode: awsvpc
      TaskRoleArn: !Sub ${ApplicationTaskRole.Arn}
      Volumes:
        - Name: public
      ContainerDefinitions:
        - Name: todobackend
          ...
          ...
 PortMappings:
 - ContainerPort: 8000 
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: !Sub /${AWS::StackName}/ecs/todobackend
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: docker
        - Name: collectstatic
          Essential: false
...
...
```

配置 ECS 任务定义以使用任务网络

在上面的示例中，`NetworkMode`属性已添加并配置为`awsvpc`的值。默认情况下，此属性设置为`bridge`，实现了默认的 Docker 行为，如第一个图中所示，包括一个 Docker 桥接口，并配置了网络地址转换以启用动态端口映射。通过将网络模式设置为`awsvpc`，ECS 将确保从此任务定义部署的任何 ECS 任务都分配了专用的弹性网络接口（ENI），并配置任务定义中的容器以使用 ENI 的网络堆栈。此示例中的另一个配置更改是从`PortMappings`部分中删除了`HostPort: 0`配置，因为 ECS 任务网络不使用或支持动态端口映射。

# 为任务网络配置 ECS 服务

将 ECS 任务定义配置为使用正确的任务网络模式后，接下来需要配置 ECS 服务。您的 ECS 服务配置定义了 ECS 应该创建 ENI 的目标子网，并且还定义了应该应用于 ENI 的安全组。以下示例演示了在 todobackend 堆栈中更新`ApplicationService`资源：

```
...
...
Resources:
  ...
  ...
  ApplicationService:
    Type: AWS::ECS::Service
    DependsOn:
      - ApplicationAutoscaling
      - ApplicationLogGroup
      - ApplicationLoadBalancerHttpListener
      - MigrateTask
    Properties:
      TaskDefinition: !Ref ApplicationTaskDefinition
      Cluster: !Ref ApplicationCluster
      DesiredCount: !Ref ApplicationDesiredCount
      NetworkConfiguration:
 AwsvpcConfiguration:
 SecurityGroups:
 - !Ref ApplicationSecurityGroup
 Subnets:
            - !Ref PrivateSubnet
      LoadBalancers:
        - ContainerName: todobackend
          ContainerPort: 8000
          TargetGroupArn: !Ref ApplicationServiceTargetGroup
 # The Role property has been removed
      DeploymentConfiguration:
        MaximumPercent: 200
        MinimumHealthyPercent: 100
...
...
```

配置 ECS 服务以使用任务网络

在前面的例子中，向 ECS 服务定义添加了一个名为`NetworkConfiguration`的新属性。每当您启用任务网络时，都需要此属性，并且您可以看到需要配置与 ECS 将创建的 ENI 相关联的子网和安全组。请注意，您引用了本章前面创建的`PrivateSubnet`资源，这确保您的容器网络接口不会直接从互联网访问。一个不太明显的变化是`Role`属性已被移除 - 每当您使用使用 ECS 任务网络的 ECS 服务时，AWS 会自动配置 ECS 角色，并且如果您尝试设置此角色，将会引发错误。

# 为任务网络配置支持资源

如果您回顾一下前面的例子，您会注意到您引用了一个名为`ApplicationSecurityGroup`的新安全组，需要将其添加到您的模板中，如下例所示：

```
...
...
 ApplicationSecurityGroup:
Type: AWS::EC2::SecurityGroup
 Properties:
 GroupDescription: !Sub ${AWS::StackName} Application Security Group
 VpcId: !Ref VpcId
 SecurityGroupEgress:
 - IpProtocol: udp
 FromPort: 53
 ToPort: 53
 CidrIp: 0.0.0.0/0
 - IpProtocol: tcp
 FromPort: 443
 ToPort: 443
 CidrIp: 0.0.0.0/0
  ...
  ...
  ApplicationLoadBalancerToApplicationIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      IpProtocol: tcp
 FromPort: 8000
 ToPort: 8000
 GroupId: !Ref ApplicationSecurityGroup
      SourceSecurityGroupId: !Ref ApplicationLoadBalancerSecurityGroup
  ApplicationLoadBalancerToApplicationEgress:
    Type: AWS::EC2::SecurityGroupEgress
    Properties:
      IpProtocol: tcp
 FromPort: 8000
 ToPort: 8000
      GroupId: !Ref ApplicationLoadBalancerSecurityGroup
 DestinationSecurityGroupId: !Ref ApplicationSecurityGroup
  ...
  ...
  ApplicationToApplicationDatabaseIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      IpProtocol: tcp
      FromPort: 3306
      ToPort: 3306
      GroupId: !Ref ApplicationDatabaseSecurityGroup
 SourceSecurityGroupId: !Ref ApplicationSecurityGroup
  ApplicationToApplicationDatabaseEgress:
    Type: AWS::EC2::SecurityGroupEgress
    Properties:
      IpProtocol: tcp
      FromPort: 3306
      ToPort: 3306
```

```
GroupId: !Ref ApplicationSecurityGroup
      DestinationSecurityGroupId: !Ref ApplicationDatabaseSecurityGroup
...
...
```

为任务网络配置安全组

在前面的例子中，您首先创建了一个安全组，其中包括一个出站规则集，允许出站 DNS 和 HTTPS 流量，这是必需的，以允许您容器中的入口脚本与 AWS Secrets Manager API 进行通信。请注意，您需要修改现有的`AWS::EC2::SecurityGroupIngress`和`AWS::EC2::SecurityGroupEgress`资源，这些资源之前允许应用负载均衡器/应用数据库与应用自动扩展组实例之间的访问。您可以看到，对于`ApplicationLoadBalancerToApplicationEgress`和`ApplicationLoadBalancerToApplicationEgress`资源，端口范围已从`32768`的临时端口范围减少到`60999`，仅为端口`8000`，这导致了更安全的配置。此外，ECS 容器实例控制平面（与`ApplicationAutoscalingSecurityGroup`资源相关联）现在无法访问您的应用数据库（现在只有您的应用可以这样做），这再次更安全。

当前对 todobackend 堆栈的修改存在一个问题，即您尚未更新`MigrateTaskDefinition`以使用任务网络。我之所以不这样做的主要原因是因为这将需要您的 ECS 容器实例支持比免费套餐 t2.micros 支持的更多弹性网络接口，并且还需要更新 ECS 任务运行器自定义资源以支持运行临时 ECS 任务。当然，如果您想在生产环境中使用 ECS 任务网络，您需要解决这些问题，但是出于提供对 ECS 任务网络的基本理解的目的，我选择不这样做。这意味着如果您进行任何需要运行迁移任务的更改，它将失败，并且一旦本章完成，您将恢复 todobackend 堆栈配置，以确保不使用 ECS 任务网络来完成剩余的章节。

最后，您需要对模板进行最后一次更改，即修改与 ECS 服务关联的应用程序负载均衡器目标组。当您的 ECS 服务运行在`awsvpc`网络模式下的任务时，您必须将目标组类型从默认值`instance`更改为`ip`的值，如下例所示，因为您的 ECS 任务现在具有自己独特的 IP 地址：

```
Resources:
 ...
 ...
 ApplicationServiceTargetGroup:
     Type: AWS::ElasticLoadBalancingV2::TargetGroup
     Properties:
       Protocol: HTTP
       Port: 8000
       VpcId: !Ref VpcId
       TargetType: ip
       TargetGroupAttributes:
         - Key: deregistration_delay.timeout_seconds
           Value: 30
 ...
 ...
```

更新应用程序负载均衡器目标组目标类型

# 部署和测试 ECS 任务网络

您现在可以部署更改并验证 ECS 任务网络是否正常工作。如果运行`aws cloudformation deploy`命令，应该会发生以下情况：

+   将创建应用程序任务定义的新修订版本，该版本配置为 ECS 任务网络。

+   ECS 服务配置将检测更改并尝试部署新的修订版本，以及 ECS 服务配置更改。ECS 将动态地将新的 ENI 附加到私有子网，并将此 ENI 分配给`ApplicationService`资源的新 ECS 任务。

部署完成后，您应该验证应用程序仍在正常工作，一旦完成此操作，您可以浏览到 ECS 控制台，单击您的 ECS 服务，并选择服务的当前运行任务。

以下屏幕截图显示了 ECS 任务屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/08553c56-6741-4783-b651-bb2a69b13d8b.png)ECS 任务处于任务网络模式

如您所见，任务的网络模式现在是`awsvpc`，并且已经从本章前面创建的私有子网中动态分配了一个 ENI。如果您点击 ENI ID 链接，您将能够验证附加到 ENI 的安全组，并且还可以检查 ENI 是否已附加到您的某个 ECS 容器实例中。

在这一点上，您应该将在本章中进行的最终一组更改提交到 ECS 任务网络分支，检出主分支，并重新部署您的 CloudFormation 堆栈。这将撤消本章中所做的所有更改，将您的堆栈恢复到上一章末尾时的相同状态。这是必需的，因为我们不希望不得不升级到更大的实例类型来适应`MigrateTaskDefinition`资源和我们将在后续章节中测试的未来自动扩展方案：

```
> git commit -a -m "Add ECS task networking resources"
 [ecs-task-networking 7e995cb] Add ECS task networking resources
 2 files changed, 37 insertions(+), 10 deletions(-)
> git checkout master
Switched to branch 'master'
> aws cloudformation deploy --template-file stack.yml --stack-name todobackend \
 --parameter-overrides $(cat dev.cfg) --capabilities CAPABILITY_NAMED_IAM

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - todobackend
```

还原 todobackend-aws 存储库

# 摘要

在本章中，您学会了如何使用 ECS 任务网络增加 Docker 应用程序的网络隔离和安全性。ECS 任务网络将默认的 Docker 桥接和 NAT 网络配置更改为每个 ECS 任务接收自己的专用弹性网络接口或 ENI 的模型。这意味着您的 Docker 应用程序被分配了自己的专用安全组，并且可以通过其发布的端口直接访问，这避免了实现动态端口映射等功能的需要，这些功能可能会影响性能并需要更宽松的安全规则才能工作。然而，ECS 任务网络也带来了一系列挑战和限制，包括更复杂的网络拓扑来适应当前仅支持私有 IP 地址的限制，以及每个 ENI 只能运行单个 ECS 任务的能力。

ECS 任务网络目前不支持公共 IP 地址，这意味着如果您的任务需要出站互联网连接，您必须提供 NAT 网关或 HTTP 代理。NAT 网关是 AWS 提供的托管服务，您学会了如何配置用于 ECS 任务的私有子网，以及如何配置私有路由表将互联网流量路由到您在现有公共子网中创建的 NAT 网关。

您已经了解到，配置 ECS 任务网络需要在 ECS 任务定义中指定 awsvpc 网络模式，并且需要向 ECS 服务添加网络配置，指定 ECS 任务将连接到的子网和将应用的安全组。如果您的应用由应用负载均衡器提供服务，您还需要确保与 ECS 服务关联的目标组的目标类型配置为`ip`，而不是默认的`instance`目标类型。如果您要将这些更改应用到现有环境中，您可能还需要更新附加到资源的安全组，例如负载均衡器和数据库，因为您的 ECS 任务不再与应用于 ECS 容器实例级别的安全组相关联，并且具有自己的专用安全组。

在接下来的两章中，您将学习如何处理 ECS 的一些更具挑战性的运营方面，包括管理 ECS 容器实例的生命周期和对 ECS 集群进行自动扩展。

# 问题

1.  真/假：默认的 Docker 网络配置使用 iptables 执行网络地址转换。

1.  您有一个应用程序，形成应用程序级别的集群，并使用 EC2 元数据来发现运行您的应用程序的其他主机的 IP 地址。当您使用 ECS 运行应用程序时，您会注意到您的应用程序正在使用`172.16.x.x/16`地址，但您的 EC2 实例配置为`172.31.x.x/16`地址。哪些 Docker 网络模式可以帮助解决这个问题？

1.  真/假：在 ECS 任务定义的`NetworkMode`中，`host`值启用了 ECS 任务网络。

1.  您为 ECS 任务定义启用了 ECS 任务网络，但是您的应用负载均衡器无法再访问您的应用程序。您检查了附加到 ECS 容器实例的安全组的规则，并确认您的负载均衡器被允许访问您的应用程序。您如何解决这个问题？

1.  您为 ECS 任务定义启用了 ECS 任务网络，但是您的容器在启动时失败，并显示无法访问位于互联网上的位置的错误。您如何解决这个问题？

1.  在 t2.micro 实例上最大可以运行多少个 ENI？

1.  在 t2.micro 实例上以任务网络模式运行的 ECS 任务的最大数量是多少？

1.  在 t2.micro 实例上以任务网络模式运行的最大容器数量是多少？

1.  启用 ECS 任务网络模式后，您收到一个部署错误，指示目标组具有目标类型实例，与 awsvpc 网络模式不兼容。您如何解决这个问题？

1.  启用 ECS 任务网络模式后，您收到一个部署错误，指出您不能为需要服务关联角色的服务指定 IAM 角色。您如何解决这个问题？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   Docker 网络概述：[`docs.docker.com/network/`](https://docs.docker.com/network/)

+   使用 awsvpc 网络模式的任务网络：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-networking.html)

+   底层原理：Amazon ECS 的任务网络：[`aws.amazon.com/blogs/compute/under-the-hood-task-networking-for-amazon-ecs/`](https://aws.amazon.com/blogs/compute/under-the-hood-task-networking-for-amazon-ecs/)

+   EC2 实例类型的最大网络接口：[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html#AvailableIpPerENI)

+   NAT 网关：[`docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-nat-gateway.html`](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-nat-gateway.html)

+   CloudFormation NAT 网关资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-natgateway.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-natgateway.html)

+   CloudFormation EC2 弹性 IP 地址资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-eip.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-eip.html)

+   CloudFormation EC2 子网资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html)

+   CloudFormation EC2 子网路由表关联资源参考: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet-route-table-assoc.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet-route-table-assoc.html)

+   CloudFormation EC2 路由表资源参考: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-route-table.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-route-table.html)

+   CloudFormation EC2 路由资源参考: [`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-route.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-route.html)

+   为 Amazon ECS 使用服务关联角色: [`docs.aws.amazon.com/AmazonECS/latest/developerguide/using-service-linked-roles.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using-service-linked-roles.html)


# 第十一章：管理 ECS 基础设施生命周期

与操作 ECS 基础设施相关的一个基本持续活动是管理 ECS 容器实例的生命周期。在任何生产级别的场景中，您都需要对 ECS 容器实例进行打补丁，并确保 ECS 容器实例的核心组件（如 Docker 引擎和 ECS 代理）经常更新，以确保您可以访问最新功能和安全性和性能增强。在一个不可变基础设施的世界中，您的 ECS 容器实例被视为“牲畜”，标准方法是通过滚动新的 Amazon 机器映像（AMIs）销毁和替换 ECS 容器实例，而不是采取传统的打补丁“宠物”方法，并将 ECS 容器实例保留很长时间。另一个常见的用例是需要管理生命周期的与自动扩展相关，例如，如果您在高需求期后扩展 ECS 集群，您需要能够从集群中移除 ECS 容器实例。

将 ECS 容器实例从服务中移除听起来可能是一个很简单的任务，然而请考虑一下如果您的实例上有正在运行的容器会发生什么。如果立即将实例移出服务，连接到运行在这些容器上的应用程序的用户将会受到干扰，这可能会导致数据丢失，至少会让用户感到不满。所需的是一种机制，使您的 ECS 容器实例能够优雅地退出服务，保持当前用户连接，直到可以在不影响最终用户的情况下关闭它们，然后在确保实例完全退出服务后终止实例。

在本章中，您将学习如何通过利用两个关键的 AWS 功能来实现这样的能力——EC2 自动缩放生命周期钩子和 ECS 容器实例排空。EC2 自动缩放生命周期钩子让您了解与启动或停止 EC2 实例相关的待处理生命周期事件，并为您提供机会在发出生命周期事件之前执行任何适当的初始化或清理操作。这就是您可以利用 ECS 容器实例排空的地方，它将受影响的 ECS 容器实例上的 ECS 任务标记为排空或停用，并开始优雅地将任务从服务中取出，方法是在集群中的其他 ECS 容器实例上启动新的替代 ECS 任务，然后排空到受影响的 ECS 任务的连接，直到任务可以停止并且 ECS 容器实例被排空。

将涵盖以下主题：

+   理解 ECS 基础设施的生命周期管理

+   构建新的 ECS 容器实例 AMI

+   配置 EC2 自动缩放滚动更新

+   创建 EC2 自动缩放生命周期钩子

+   创建用于消耗生命周期钩子的 Lambda 函数

+   部署和测试自动缩放生命周期钩子

# 技术要求

以下列出了完成本章所需的技术要求：

+   AWS 账户的管理员访问

+   根据第三章的说明配置本地 AWS 配置文件

+   AWS CLI 版本 1.15.71 或更高版本

+   本章继续自第九章（而不是第十章），因此需要您成功完成第九章中定义的所有配置任务，并确保您已将**todobackend-aws**存储库重置为主分支（应基于第九章的完成）

以下 GitHub URL 包含本章中使用的代码示例 - [`github.com/docker-in-aws/docker-in-aws/tree/master/ch11`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch11)[.](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch4)

查看以下视频以查看代码的实际操作：

[`bit.ly/2BT7DVh`](http://bit.ly/2BT7DVh)

# 理解 ECS 生命周期管理

如本章介绍中所述，ECS 生命周期管理是指将现有的 ECS 容器实例从服务中取出的过程，而不会影响连接到在您受影响的实例上运行的应用程序的最终用户。

这需要您利用 AWS 提供的两个关键功能：

+   EC2 自动扩展生命周期挂钩

+   ECS 容器实例排水

# EC2 自动扩展生命周期挂钩

EC2 自动扩展生命周期挂钩允许您在挂起的生命周期事件发生之前收到通知并在事件发生之前执行某些操作。目前，您可以收到以下生命周期挂钩事件的通知：

+   `EC2_INSTANCE_LAUNCHING`：当 EC2 实例即将启动时引发

+   `EC2_INSTANCE_TERMINATING`：当 EC2 实例即将终止时引发

一般情况下，您不需要担心`EC2_INSTANCE_LAUNCHING`事件，但是任何运行生产级 ECS 集群的人都应该对`EC2_INSTANCE_TERMINATING`事件感兴趣，因为即将终止的实例可能正在运行具有活动最终用户连接的容器。一旦您订阅了生命周期挂钩事件，EC2 自动扩展服务将等待您发出信号，表明生命周期操作可以继续进行。这为您提供了一种机制，允许您在`EC2_INSTANCE_TERMINATING`事件发生时执行优雅的拆除操作，这就是您可以利用 ECS 容器实例排水的地方。

# ECS 容器实例排水

ECS 容器实例排水是一个功能，允许您优雅地排水您的 ECS 容器实例中正在运行的 ECS 任务，最终结果是您的 ECS 容器实例没有正在运行的 ECS 任务或容器，这意味着可以安全地终止实例而不影响您的容器应用程序。ECS 容器实例排水首先将您的 ECS 容器实例标记为 DRAINING 状态，这将导致在实例上运行的所有 ECS 任务被优雅地关闭并在集群中的其他容器实例上启动。这种排水活动使用了您已经在 ECS 服务中看到的标准*滚动*行为，例如，如果您有一个与具有应用程序负载均衡器集成的 ECS 服务相关联的 ECS 任务，ECS 将首先尝试在另一个 ECS 容器实例上注册一个新的 ECS 任务作为应用程序负载均衡器目标组中的新目标，然后将与正在排水的 ECS 容器实例相关联的目标放置到连接排水状态。

请注意，重要的是您的 ECS 集群具有足够的资源和 ECS 容器实例来迁移每个受影响的 ECS 任务，这可能具有挑战性，因为您还通过一个实例减少了 ECS 集群的容量。这意味着，例如，如果您正在计划替换集群中的 ECS 容器实例（例如，您正在更新到新的 AMI），那么您需要临时向集群添加额外的容量，以便以滚动方式交换实例，而不会减少整体集群容量。如果您正在使用 CloudFormation 部署您的 EC2 自动扩展组，一个非常有用的功能是能够指定更新策略，在滚动更新期间临时向您的自动扩展组添加额外的容量，您将学习如何利用此功能始终确保在执行滚动更新时始终保持 ECS 集群容量。

# ECS 生命周期管理解决方案

现在您已经了解了 ECS 生命周期管理的一些背景知识，让我们讨论一下您将在本章中实施的解决方案，该解决方案将利用 EC2 生命周期挂钩来触发 ECS 容器实例的排空，并在安全终止 ECS 容器实例时向 EC2 自动扩展服务发出信号。

以下图表说明了一个简单的 EC2 自动扩展组和一个具有两个 ECS 容器实例的 ECS 集群，支持 ECS **Service A**和 ECS **Service B**，它们都有两个 ECS 任务或 ECS 服务的实例正在运行：

在服务中的 EC2 自动扩展组/ECS 集群

假设您现在希望使用新的 Amazon Machine Image 更新 EC2 自动扩展组中的 ECS 容器实例，这需要终止并替换每个实例。以下图表说明了我们的生命周期挂钩解决方案将如何处理这一要求，并确保自动扩展组中的每个实例都可以以不干扰连接到每个 ECS 服务的应用程序的最终用户的方式进行替换：

执行滚动更新的在服务中的 EC2 自动扩展组/ECS 集群

在上图中，发生以下步骤：

1.  CloudFormation 滚动更新已配置为 EC2 自动扩展组，这会导致 CloudFormation 服务临时增加 EC2 自动扩展组的大小。

1.  EC2 自动扩展组根据 CloudFormation 中组大小的增加，向自动扩展组添加一个新的 EC2 实例（ECS 容器实例 C）。

1.  一旦新的 EC2 实例启动并向 CloudFormation 发出成功信号，CloudFormation 服务将指示 EC2 自动扩展服务终止 ECS 容器实例 A，因为 ECS 容器实例 C 现在已加入 EC2 自动扩展组和 ECS 集群。

1.  在终止实例之前，EC2 自动扩展服务触发一个生命周期挂钩事件，将此事件发布到配置的简单通知服务（SNS）主题。SNS 是一种发布/订阅样式的通知服务，可用于各种用例，在我们的解决方案中，我们将订阅一个 Lambda 函数到 SNS 主题。

1.  Lambda 函数是由 SNS 主题调用的，以响应生命周期挂钩事件被发布到主题。

1.  Lambda 函数指示 ECS 排空即将被终止的 ECS 容器实例。然后，该函数轮询 ECS 容器实例上正在运行的任务数量，等待任务数量为零后才认为排空过程完成。

1.  ECS 将正在运行在 ECS 容器实例 A 上的当前任务转移到具有空闲容量的其他容器实例。在上图中，由于 ECS 容器实例 C 最近被添加到集群中，因此正在运行在 ECS 容器实例 A 上的 ECS 任务可以被转移到容器实例 C。请注意，如果容器实例 C 尚未添加到集群中，集群中将没有足够的容量来转移容器实例 A，因此确保集群具有足够的容量来处理这些类型的事件非常重要。

1.  在许多情况下，ECS 容器实例的排空可能会超过 Lambda 的当前五分钟执行超时限制。在这种情况下，您可以简单地重新发布生命周期挂钩事件通知到 SNS 主题，这将自动重新调用 Lambda 函数。

1.  Lambda 函数再次指示 ECS 排空容器实例 A（已在进行中），并继续轮询运行任务数量，等待运行任务数量为零。

1.  假设容器实例完成排空并且运行任务数量减少为零，Lambda 函数会向 EC2 自动扩展服务发出生命周期挂钩已完成的信号。

1.  EC2 自动缩放服务现在终止 ECS 容器实例，因为生命周期挂钩已经完成。

此时，由 CloudFormation 在步骤 1 中发起的滚动更新已经完成了 50%，因为旧的 ECS 容器实例 A 已被 ECS 容器实例 C 替换。在前面的图表中描述的过程再次重复，引入了一个新的 ECS 容器实例到集群中，并将 ECS 容器实例 B 标记为终止。一旦 ECS 容器实例 B 的排空完成，自动缩放组/集群中的所有实例都已被替换，滚动更新完成。

# 构建一个新的 ECS 容器实例 AMI

为了测试我们的生命周期管理解决方案，我们需要有一种机制来强制终止您的 ECS 容器实例。虽然您可以简单地调整自动缩放组的期望计数（实际上这是自动缩放组缩减时的常见情况），但另一种常见情况是当您需要通过引入一个新构建的 Amazon Machine Image（AMI）来更新您的 ECS 容器实例，其中包括最新的操作系统和安全补丁，以及最新版本的 Docker Engine 和 ECS 代理。至少，如果您正在使用类似于第六章中学到的方法构建自定义 ECS 容器实例 AMI，那么每当 Amazon 发布基本 ECS 优化 AMI 的新版本时，您都应该重新构建您的 AMI，并且每周或每月更新您的 AMI 是常见做法。

要模拟将新的 AMI 引入 ECS 集群，您可以简单地执行第六章中执行的相同步骤，这将输出一个新的 AMI，然后您可以将其作为输入用于您的堆栈，并强制您的 ECS 集群升级每个 ECS 容器实例。

以下示例演示了从**packer-ecs**存储库的根目录运行`make build`命令，这将输出一个新的 AMI ID，用于新创建和发布的镜像。确保您记下这个 AMI ID，因为您稍后在本章中会需要它：

```
> export AWS_PROFILE=docker-in-aws
> make build
packer build packer.json
amazon-ebs output will be in this color.

==> amazon-ebs: Prevalidating AMI Name: docker-in-aws-ecs 1518934269
...
...
Build 'amazon-ebs' finished.

==> Builds finished. The artifacts of successful builds are:
--> amazon-ebs: AMIs were created:
us-east-1: ami-77893508
```

运行 Packer 构建

# 配置 EC2 自动缩放滚动更新

当您使用 CloudFormation 创建和管理您的 EC2 自动扩展组时，一个有用的功能是能够管理滚动更新。滚动更新是指以受控的方式将新的 EC2 实例*滚入*您的自动扩展组，以确保您的更新过程可以在不引起中断的情况下完成。在第八章，当您通过 CloudFormation 创建 EC2 自动扩展组时，您了解了 CloudFormation 支持创建策略，可以帮助您确保 EC2 自动扩展中的所有实例都已成功初始化。CloudFormation 还支持更新策略，正如您在前面的图表中看到的那样，它可以帮助您管理和控制对 EC2 自动扩展组的更新。

如果您打开 todobackend-aws 存储库并浏览到`stack.yml`文件中的 CloudFormation 模板，您可以向`ApplicationAutoscaling`资源添加更新策略，如以下示例所示：

```
...
...
Resources:
  ...
  ...
  ApplicationAutoscaling:
    Type: AWS::AutoScaling::AutoScalingGroup
    CreationPolicy:
      ResourceSignal:
        Count: !Ref ApplicationDesiredCount
        Timeout: PT15M
    UpdatePolicy:
 AutoScalingRollingUpdate:
 MinInstancesInService: !Ref ApplicationDesiredCount
 MinSuccessfulInstancesPercent: 100
 WaitOnResourceSignals: "true"
 PauseTime: PT15M
  ...
  ...
```

配置 CloudFormation 自动扩展组更新策略

在上面的示例中，`UpdatePolicy`设置应用于`ApplicationAutoscaling`资源，该资源配置 CloudFormation 根据以下`AutoScalingRollingUpdate`配置参数来编排滚动更新，每当自动扩展组中的实例需要被替换（*更新*）时：

+   `MinInstancesInService`：在滚动更新期间必须处于服务状态的最小实例数。这里的标准方法是指定自动扩展组的期望计数，这意味着自动扩展将临时增加大小，以便在添加新实例时保持所需实例的最小数量。

+   `MinSuccessfulInstancesPercent`：必须成功部署的新实例的最低百分比，以便将滚动更新视为成功。如果未达到此百分比，则 CloudFormation 将回滚堆栈更改。

+   `WaitOnResourceSignals`：当设置为 true 时，指定 CloudFormation 在考虑实例成功部署之前等待每个实例发出的成功信号。这需要您的 EC2 实例在第六章安装并在第七章配置的`cfn-bootstrap`脚本向 CloudFormation 发出信号，表示实例初始化已完成。

+   `PauseTime`：当配置了`WaitOnResourceSignals`时，指定等待每个实例发出 SUCCESS 信号的最长时间。此值以 ISO8601 格式表示，在下面的示例中配置为等待最多 15 分钟。

然后，使用`aws cloudformation deploy`命令部署您的更改，如下例所示，您的自动扩展组现在将应用更新策略：

```
> export AWS_PROFILE=docker-in-aws
> aws cloudformation deploy --template-file stack.yml \
 --stack-name todobackend --parameter-overrides $(cat dev.cfg) \
 --capabilities CAPABILITY_NAMED_IAM
Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga:

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - todobackend
  ...
  ...
```

配置 CloudFormation 自动扩展组更新策略

此时，您现在可以更新堆栈以使用您在第一个示例中创建的新 AMI。这需要您首先更新 todobackend-aws 存储库根目录下的`dev.cfg`文件：

```
ApplicationDesiredCount=1
ApplicationImageId=ami-77893508
ApplicationImageTag=5fdbe62
ApplicationSubnets=subnet-a5d3ecee,subnet-324e246f
VpcId=vpc-f8233a80
```

更新 ECS AMI

然后，使用相同的`aws cloudformation deploy`命令部署更改。

在部署运行时，如果您打开 AWS 控制台，浏览到 CloudFormation 仪表板，并选择 todobackend 堆栈**事件**选项卡，您应该能够看到 CloudFormation 如何执行滚动更新：

CloudFormation 滚动更新

在前面的屏幕截图中，您可以看到 CloudFormation 首先临时增加了自动扩展组的大小，因为它需要始终保持至少一个实例在服务中。一旦新实例向 CloudFormation 发出 SUCCESS 信号，自动扩展组中的旧实例将被终止，滚动更新就完成了。

此时，您可能会感到非常高兴——只需对 CloudFormation 配置进行小小的更改，您就能够为堆栈添加滚动更新。不过，有一个问题，就是旧的 EC2 实例被立即终止。这实际上会导致服务中断，如果您导航到 CloudWatch 控制台，选择指标，在所有指标选项卡中选择 ECS **|** ClusterName，然后选择名为 todobackend-cluster 的集群的 MemoryReservation 指标，您可以看到这种迹象。

在您单击图形化指标选项卡并将统计列更改为最小值，周期更改为 1 分钟后，将显示以下屏幕截图：

ECS 内存预留

如果您回顾之前的屏幕截图中的时间线，您会看到在 21:17:33 旧的 ECS 容器实例被终止，在之前的屏幕截图中，您可以看到集群内存预留在 21:18（09:18）降至 0%。这表明在这个时间点上，没有实际的容器在运行，因为集群内存保留的百分比为 0，这表明在旧实例突然终止后，ECS 尝试将 todobackend 服务恢复到新的 ECS 容器实例时出现了短暂的中断。

因为最小的 CloudWatch 指标分辨率是 1 分钟，如果 ECS 能够在一分钟内恢复 ECS 服务，您可能无法观察到在前一个图表中降至 0%的情况，但请放心，您的应用程序确实会中断。

显然，这并不理想，正如我们之前讨论的那样，我们现在需要引入 EC2 自动扩展生命周期挂钩来解决这种情况。

# 创建 EC2 自动扩展生命周期挂钩

为了解决 EC2 实例终止影响我们的 ECS 服务的问题，我们现在需要创建一个 EC2 自动扩展生命周期挂钩，它将通知我们 EC2 实例即将被终止。回顾第一个图表，这需要几个资源：

+   实际的生命周期挂钩

+   授予 EC2 自动扩展组权限向 SNS 主题发布生命周期挂钩通知的生命周期挂钩角色

+   SNS 主题，生命周期挂钩可以发布和订阅

以下示例演示了创建生命周期挂钩、生命周期挂钩角色和 SNS 主题：

```
...
...
Resources:
  ...
  ...
 LifecycleHook:
 Type: AWS::AutoScaling::LifecycleHook
 Properties:
 RoleARN: !Sub ${LifecycleHookRole.Arn}
 AutoScalingGroupName: !Ref ApplicationAutoscaling
 DefaultResult: CONTINUE
 HeartbeatTimeout: 900
 LifecycleTransition: autoscaling:EC2_INSTANCE_TERMINATING
 NotificationTargetARN: !Ref LifecycleHookTopic
 LifecycleHookRole:
 Type: AWS::IAM::Role
 Properties:
 AssumeRolePolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Action:
 - sts:AssumeRole
 Effect: Allow
 Principal:
 Service: autoscaling.amazonaws.com
 Policies:
- PolicyName: LifecycleHookPermissions
 PolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Sid: PublishNotifications
 Action: 
 - sns:Publish
 Effect: Allow
 Resource: !Ref LifecycleHookTopic
 LifecycleHookTopic:
 Type: AWS::SNS::Topic
 Properties: {}
  LifecycleHookSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      Endpoint: !Sub ${LifecycleHookFunction.Arn}
      Protocol: lambda
      TopicArn: !Ref LifecycleHookTopic    ...
    ...

```

在 CloudFormation 中创建生命周期挂钩资源

在前面的示例中，`LifecycleHook`资源创建了一个新的钩子，该钩子与`ApplicationAutoscaling`资源相关联，使用`AutoScalingGroupName`属性，并由 EC2 实例触发，这些实例即将被终止，如`LifecycleTransition`属性配置的`autoscaling:EC2_INSTANCE_TERMINATING`值所指定的那样。该钩子配置为向名为`LifecycleHookTopic`的新 SNS 主题资源发送通知，链接的`LifecycleHookRole` IAM 角色授予`autoscaling.amazonaws.com`服务（如角色的`AssumeRolePolicyDocument`部分中所指定的）权限，以将生命周期钩子事件发布到此主题。`DefaultResult`属性指定了在`HeartbeatTimeout`期间到达并且没有收到钩子响应时应创建的默认结果，例如，在本示例中，发送一个`CONTINUE`消息，指示 Auto Scaling 服务继续处理可能已注册的任何其他生命周期钩子。`DefaultResult`属性的另一个选项是发送一个`ABANDON`消息，这仍然指示 Auto Scaling 服务继续进行实例终止，但放弃处理可能配置的任何其他生命周期钩子。

最终的`LifecycleHookSubscription`资源创建了对`LifecycleHookTopic` SNS 主题资源的订阅，订阅了一个名为`LifecycleHookFunction`的 Lambda 函数资源，我们将很快创建，这意味着每当消息发布到 SNS 主题时，将调用此函数。

# 创建用于消耗生命周期钩子的 Lambda 函数

有了各种生命周期钩子资源，谜题的最后一块是创建一个 Lambda 函数和相关资源，该函数将订阅您在上一节中定义的生命周期钩子 SNS 主题，并最终在发出信号表明生命周期钩子操作可以继续之前执行 ECS 容器实例排空。

让我们首先关注 Lambda 函数本身以及它将需要执行的相关源代码：

```
...
...
Resources: LifecycleHookFunction:
    Type: AWS::Lambda::Function
    DependsOn:
      - LifecycleHookFunctionLogGroup
    Properties:
      Role: !Sub ${LifecycleFunctionRole.Arn}
      FunctionName: !Sub ${AWS::StackName}-lifecycleHooks
      Description: !Sub ${AWS::StackName} Autoscaling Lifecycle Hook
      Environment:
        Variables:
          ECS_CLUSTER: !Ref ApplicationCluster
      Code:
        ZipFile: |
          import os, time
          import json
          import boto3
          cluster = os.environ['ECS_CLUSTER']
          # AWS clients
          ecs = boto3.client('ecs')
          sns = boto3.client('sns')
          autoscaling = boto3.client('autoscaling')

          def handler(event, context):
            print("Received event %s" % event)
            for r in event.get('Records'):
              # Parse SNS message
              message = json.loads(r['Sns']['Message'])
              transition, hook = message['LifecycleTransition'], message['LifecycleHookName']
              group, ec2_instance = message['AutoScalingGroupName'], message['EC2InstanceId']
              if transition != 'autoscaling:EC2_INSTANCE_TERMINATING':
                print("Ignoring lifecycle transition %s" % transition)
                return
              try:
                # Get ECS container instance ARN
                ecs_instance_arns = ecs.list_container_instances(
                  cluster=cluster
                )['containerInstanceArns']
                ecs_instances = ecs.describe_container_instances(
                  cluster=cluster,
                  containerInstances=ecs_instance_arns
                )['containerInstances']
                # Find ECS container instance with same EC2 instance ID in lifecycle hook message
                ecs_instance_arn = next((
                  instance['containerInstanceArn'] for instance in ecs_instances
                  if instance['ec2InstanceId'] == ec2_instance
                ), None)
                if ecs_instance_arn is None:
                  raise ValueError('Could not locate ECS instance')
                # Drain instance
                ecs.update_container_instances_state(
                  cluster=cluster,
                  containerInstances=[ecs_instance_arn],
                  status='DRAINING'
                )
                # Check task count on instance every 5 seconds
                count = 1
                while count > 0 and context.get_remaining_time_in_millis() > 10000:
                  status = ecs.describe_container_instances(
                    cluster=cluster,
                    containerInstances=[ecs_instance_arn],
                  )['containerInstances'][0]
                  count = status['runningTasksCount']
                  print("Sleeping...")
                  time.sleep(5)
                if count == 0:
                  print("All tasks drained - sending CONTINUE signal")
                  autoscaling.complete_lifecycle_action(
                    LifecycleHookName=hook,
                    AutoScalingGroupName=group,
                    InstanceId=ec2_instance,
                    LifecycleActionResult='CONTINUE'
                  )
                else:
                  print("Function timed out - republishing SNS message")
                  sns.publish(TopicArn=r['Sns']['TopicArn'], Message=r['Sns']['Message'])
              except Exception as e:
                print("A failure occurred with exception %s" % e)
                autoscaling.complete_lifecycle_action(
                  LifecycleHookName=hook,
                  AutoScalingGroupName=group,
                  InstanceId=ec2_instance,
                  LifecycleActionResult='ABANDON'
                )
      Runtime: python3.6
      MemorySize: 128
      Timeout: 300
      Handler: index.handler
  LifecycleHookFunctionLogGroup:
    Type: AWS::Logs::LogGroup
    DeletionPolicy: Delete
    Properties:
      LogGroupName: !Sub /aws/lambda/${AWS::StackName}-lifecycleHooks
      RetentionInDays: 7    ...
    ...

```

创建用于处理生命周期钩子的 Lambda 函数

Lambda 函数比我们迄今为止处理的要复杂一些，但如果您有 Python 经验，它仍然是一个相对简单的函数，应该相对容易理解。

该函数首先定义所需的库，并查找名为`ECS_CLUSTER`的环境变量，这是必需的，以便函数知道生命周期挂钩与哪个 ECS 集群相关，并且通过 Lambda 函数资源的`Environment`属性传递此环境变量值。

接下来，函数声明了三个 AWS 客户端：

+   `ecs`：与 ECS 通信，以审查 ECS 容器实例信息并根据生命周期挂钩中接收的 EC2 实例 ID 排空正确的实例。

+   `autoscaling`：在生命周期挂钩可以继续时，向 EC2 自动缩放服务发出信号。

+   `sns`：如果 Lambda 函数即将达到最长五分钟的执行超时，并且 ECS 容器实例尚未排空，则重新发布生命周期挂钩事件。这将再次调用 Lambda 函数，直到 ECS 容器实例完全排空。

`handler`方法定义了 Lambda 函数的入口点，并首先提取出许多变量，这些变量从接收到的 SNS 消息中捕获信息，包括生命周期挂钩事件类型（`transition`变量）、挂钩名称（`hook`变量）、Auto Scaling 组名称（`group`变量）和 EC2 实例 ID（`ec2_instance`变量）。然后立即进行检查，以验证生命周期挂钩事件类型是否与 EC2 实例终止事件相关，如果事件类型（在 transition 变量中捕获）不等于值`autoscaling:EC2_INSTANCE_TERMINATING`，则函数立即返回，有效地忽略该事件。

假设事件确实与 EC2 实例的终止有关，处理程序接下来通过`ecs`客户端查询 ECS 服务，首先描述配置集群中的所有实例，然后尝试定位与生命周期挂钩事件捕获的 EC2 实例 ID 匹配的 ECS 容器实例。如果找不到实例，则会引发`ValueError`异常，该异常将被 catch 语句捕获，导致记录错误并使用`ABANDON`的结果完成生命周期挂钩。如果找到实例，处理程序将继续通过在`ecs`客户端上调用`update_container_instances_state()`方法来排水实例，该方法将实例的状态设置为`DRAINING`，这意味着 ECS 将不再将任何新任务调度到该实例，并尝试将现有任务迁移到集群中的其他实例。在这一点上，处理程序需要等待在实例上运行的所有当前 ECS 任务被排水，这可以通过每五秒轮询一次 ECS 任务计数的`while`循环来实现，直到任务计数减少到零。您可以无限期地尝试这样做，但是在撰写本文时，Lambda 具有最长五分钟的执行时间限制，因此`while`循环使用`context.get_remaining_time_in_millis()`方法来检查 Lambda 执行超时是否即将到达。

`context`对象是由 Lambda 运行时环境传递给处理程序方法的对象，其中包括有关 Lambda 环境的信息，包括内存、CPU 和剩余执行时间。

如果任务计数减少到零，您可以安全地终止 ECS 容器实例，自动缩放客户端将使用`CONTINUE`的结果完成生命周期挂钩，这意味着 EC2 自动缩放服务将继续处理任何其他注册的挂钩并终止实例。如果任务计数在函数即将退出之前没有减少到零，则函数只是重新发布原始的生命周期挂钩通知，这将重新启动函数。由于函数中的所有操作都是幂等的，即更新已经处于排水状态的 ECS 容器实例的状态为 DRAINING 会导致相同的排水状态，因此这种方法是安全的，也是克服 Lambda 执行超时限制的一种非常简单而优雅的方法。

# 为生命周期挂钩 Lambda 函数配置权限

Lambda 函数现在已经就位，最后的配置任务是为 Lambda 函数执行的各种 API 调用和操作添加所需的权限：

```
...
...
Resources: LifecycleHookPermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref LifecycleHookFunction
      Principal: sns.amazonaws.com
      SourceArn: !Ref LifecycleHookTopic
  LifecycleFunctionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Action:
              - sts:AssumeRole
            Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
      Policies:
        - PolicyName: LifecycleHookPermissions
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: ListContainerInstances
                Effect: Allow
                Action:
                  - ecs:ListContainerInstances
                Resource: !Sub ${ApplicationCluster.Arn}
              - Sid: ManageContainerInstances
                Effect: Allow
                Action:
                  - ecs:DescribeContainerInstances
                  - ecs:UpdateContainerInstancesState
                Resource: "*"
                Condition:
                  ArnEquals:
                    ecs:cluster: !Sub ${ApplicationCluster.Arn}
              - Sid: Publish
                Effect: Allow
                Action:
                  - sns:Publish
                Resource: !Ref LifecycleHookTopic
              - Sid: CompleteLifecycleAction
                Effect: Allow
                Action:
                  - autoscaling:CompleteLifecycleAction
                Resource: !Sub arn:aws:autoscaling:${AWS::Region}:${AWS::AccountId}:autoScalingGroup:*:autoScalingGroupName/${ApplicationAutoscaling}
              - Sid: ManageLambdaLogs
                Effect: Allow
                Action:
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: !Sub ${LifecycleHookFunctionLogGroup.Arn}    LifecycleHookFunction:
      Type: AWS::Lambda::Function
    ...
    ...

```

为生命周期挂钩 Lambda 函数配置权限

在前面的示例中，需要一个名为`LifecycleHookPermission`的资源，类型为`AWS::Lambda::Permission`，它授予 SNS 服务（由`Principal`属性引用）调用 Lambda 函数（由`LambdaFunction`属性引用）的权限，用于 SNS 主题发布的通知（由`SourceArn`属性引用）。每当您需要授予另一个 AWS 服务代表您调用 Lambda 函数的能力时，通常需要采用这种配置权限的方法，尽管也有例外情况（例如 CloudFormation 自定义资源用例，其中 CloudFormation 隐含具有这样的权限）。

您还需要为 Lambda 函数创建一个名为`LambdaFunctionRole`的 IAM 角色，该角色授予函数执行各种任务和操作的能力，包括：

+   列出、描述和更新应用程序集群中的 ECS 容器实例

+   如果 Lambda 函数即将超时，则重新发布生命周期挂钩事件到 SNS

+   在 ECS 容器实例排空后完成生命周期操作

+   将日志写入 CloudWatch 日志

# 部署和测试自动扩展生命周期挂钩

您现在可以使用`aws cloudformation deploy`命令部署完整的自动扩展生命周期挂钩解决方案，就像本章前面演示的那样。

部署完成后，为了测试生命周期管理是否按预期工作，您可以执行一个简单的更改，强制替换 ECS 集群中当前的 ECS 容器实例，即恢复您在本章前面所做的 AMI 更改：

```
ApplicationDesiredCount=1
ApplicationImageId=ami-ec957491
ApplicationImageTag=5fdbe62
ApplicationSubnets=subnet-a5d3ecee,subnet-324e246f
VpcId=vpc-f8233a80
```

恢复 ECS AMI

现在，一旦您部署了这个更改，再次使用`aws cloudformation deploy`命令，就像之前的示例演示的那样，接下来切换到 CloudFormation 控制台，当事件引发终止现有的 EC2 实例时，快速导航到 ECS 仪表板并选择您的 ECS 集群。在容器实例选项卡上，您应该看到您的 ECS 容器实例中的一个状态正在排空，如下面的屏幕截图所示，一旦所有任务从这个实例中排空，生命周期挂钩函数将向 EC2 自动扩展服务发出信号，以继续终止实例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/48e994f8-8700-4055-85be-dce072cd5887.png)ECS 容器实例排空

如果您重复执行前面屏幕截图中的步骤，以查看 ECS 容器实例在排空和终止期间的集群内存保留量，您应该会看到一个类似下面示例中的图表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6ce7187e-5fa4-4457-bea3-ce1220c04bb1.png)ECS 容器实例排空期间的集群内存保留

在前面的屏幕截图中，请注意在滚动更新期间，集群内存保留量从未降至 0％。由于在滚动升级期间集群中有两个实例，内存利用率百分比确实会发生变化，但我们排空 ECS 容器实例的能力确保了在集群上运行的应用程序的不间断服务。

作为最后的检查，您还可以导航到生命周期挂钩函数的 CloudWatch 日志组，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/5a4701c4-7ce4-4900-9301-222be446dc52.png)生命周期挂钩函数日志

在前面的屏幕截图中，您可以看到该函数在容器实例排空时定期休眠，大约两分钟后，在这种情况下，所有任务排空并且函数向自动扩展服务发送`CONTINUE`信号以继续挂钩。

# 摘要

在本章中，您创建了一个解决方案，用于管理 ECS 容器实例的生命周期，并确保在需要终止和替换 ECS 集群中的 ECS 容器实例时，运行在 ECS 集群上的应用程序和服务不会受到影响。

您学习了如何通过利用 CloudFormation 更新策略来配置 EC2 自动扩展组的滚动更新，从而控制新实例如何以滚动方式添加到您的自动扩展组。您发现这个功能在自动扩展和 EC2 实例级别上运行良好，但是您发现在集群中突然终止现有 ECS 容器实例会导致应用程序中断。

为了解决这个挑战，您创建了一个注册为`EC2_INSTANCE_TERMINATING`事件的 EC2 生命周期挂钩，并配置此挂钩以将通知发布到 SNS 主题，然后触发一个 Lambda 函数。该函数负责定位与即将终止的 EC2 实例相关联的 ECS 容器实例，排空容器实例，然后等待直到 ECS 任务计数达到 0，表示实例上的所有 ECS 任务都已终止并替换。如果 ECS 容器实例的执行时间超过 Lambda 函数的五分钟最大执行时间，您学会了可以简单地重新发布包含生命周期挂钩信息的 SNS 事件，这将触发函数的新调用，这个过程可以无限期地继续，直到实例上的 ECS 任务计数达到 0。

在下一章中，您将学习如何动态管理 ECS 集群的容量，这对支持应用程序的自动扩展要求至关重要。这涉及不断向您的 ECS 集群添加和删除 ECS 容器实例，因此您可以看到，本章介绍的 ECS 容器实例生命周期机制对确保您的应用程序不受任何自动扩展操作影响至关重要。

# 问题

1.  真/假：当您终止 ECS 容器实例时，该实例将自动将运行的 ECS 任务排空到集群中的另一个实例。

1.  您可以接收哪些类型的 EC2 自动扩展生命周期挂钩？

1.  一旦完成处理 EC2 自动扩展生命周期挂钩，您可以发送哪些类型的响应？

1.  真/假：EC2 自动扩展生命周期挂钩可以向 AWS Kinesis 发布事件。

1.  您创建了一个处理生命周期挂钩并排空 ECS 容器实例的 Lambda 函数。您注意到有时这需要大约 4-5 分钟，但通常需要 15 分钟。您可以采取什么措施来解决这个问题？

1.  您可以配置哪个 CloudFormation 功能以启用自动扩展组的滚动更新？

1.  您想要执行滚动更新，并确保在更新期间始终至少有当前所需数量的实例在服务中。您将如何实现这一点？

1.  在使用 CloudFormation 订阅 Lambda 函数到 SNS 主题时，您需要创建什么类型的资源以确保 SNS 服务具有适当的权限来调用函数？

# 进一步阅读

您可以查看以下链接以获取有关本章涵盖的主题的更多信息：

+   CloudFormation UpdatePolicy 属性：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html)

+   Amazon EC2 自动扩展生命周期挂钩：[`docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html`](https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html)

+   CloudFormation 生命周期挂钩资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-lifecyclehook.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-lifecyclehook.html)

+   CloudFormation SNS 主题资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-topic.html)

+   CloudFormation SNS 订阅资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html)

+   CloudFormation Lambda 权限资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html)

+   CloudFormation ECS 任务定义资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html)

+   CloudFormation ECS 服务资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html)

+   CloudFormation Lambda 函数资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html)

+   CloudFormation Lambda 函数代码：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html)

+   CloudFormation 自定义资源文档：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html)

+   CloudFormation 自定义资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref.html)


# 第十二章：ECS 自动扩展

**弹性**是云计算的基本原则之一，描述了根据需求自动扩展应用程序的能力，以确保客户获得最佳体验和响应性，同时通过仅在实际需要时提供额外容量来优化成本。

AWS 支持通过两个关键功能来扩展使用 ECS 部署的 Docker 应用程序：

+   **应用程序自动扩展**：这使用 AWS 应用程序自动扩展服务，并支持在 ECS 服务级别进行自动扩展，您的 ECS 服务运行的 ECS 任务或容器的数量可以增加或减少。

+   **EC2 自动扩展**：这使用 EC2 自动扩展服务，并支持在 EC2 自动扩展组级别进行自动扩展，您的自动扩展组中的 EC2 实例数量可以增加或减少。在 ECS 的上下文中，您的 EC2 自动扩展组通常对应于 ECS 集群，而单独的 EC2 实例对应于 ECS 容器实例，因此 EC2 自动扩展正在管理您的 ECS 集群的整体容量。

由于这里涉及两种范式，为您的 Docker 应用程序实现自动扩展可能是一个具有挑战性的技术概念，更不用说以可预测和可靠的方式成功实现了。更糟糕的是，截至撰写本书的时间，应用程序自动扩展和 EC2 自动扩展是完全独立的功能，彼此之间没有集成，因此，您需要确保这两个功能能够相互配合。

在分析这些功能时，好消息是应用程序自动扩展非常容易理解和实现。使用应用程序自动扩展，您只需定义应用程序的关键性能指标，并增加（增加）或减少（减少）运行应用程序的 ECS 任务的数量。坏消息是，当应用于在 ECS 集群中自动扩展 ECS 容器实例时，EC2 自动扩展绝对是一个更难处理的命题。在这里，您需要确保您的 ECS 集群为在集群中运行的所有 ECS 任务提供足够的计算、内存和网络资源，并确保您的集群能够在应用程序自动扩展时增加或减少容量。

扩展 ECS 集群的另一个挑战是确保您不会在缩减/缩小事件期间从集群中移除的 ECS 容器实例上中断服务并排空正在运行的任务。第十一章中实施的 ECS 生命周期挂钩解决方案会为您处理这一问题，确保在允许 EC2 自动扩展服务将实例移出服务之前，ECS 容器实例会排空所有正在运行的任务。

解决扩展 ECS 集群资源的问题是本章的主要焦点，一旦解决了这个问题，您将能够任意扩展您的 ECS 服务，并确保您的 ECS 集群会动态地添加或移除 ECS 容器实例，以确保您的应用程序始终具有足够和最佳的资源。在本章中，我们将首先专注于解决 ECS 集群容量管理的问题，然后讨论如何配置 AWS 应用程序自动扩展服务以自动扩展您的 ECS 服务和应用程序。

将涵盖以下主题：

+   了解 ECS 集群资源

+   计算 ECS 集群容量

+   实施 ECS 集群容量管理解决方案

+   配置 CloudWatch 事件以触发容量管理计算

+   发布与 ECS 集群容量相关的自定义 CloudWatch 指标

+   配置 CloudWatch 警报和 EC2 自动扩展策略以扩展您的 ECS 集群

+   配置 ECS 应用程序自动扩展

# 技术要求

以下列出了完成本章所需的技术要求：

+   AWS 账户的管理员访问权限

+   根据第三章的说明配置本地 AWS 配置文件

+   AWS CLI

+   本章是从第十一章继续下去的，因此需要您成功完成那里定义的所有配置任务。

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch12`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch12)。

查看以下视频以查看代码的实际操作：

[`bit.ly/2PdgtPr`](http://bit.ly/2PdgtPr)

# 了解 ECS 集群资源

在您开始管理 ECS 集群的容量之前，您需要清楚而牢固地了解影响 ECS 集群容量的各种资源。

一般来说，有三个关键资源需要考虑：

+   CPU

+   内存

+   网络

# CPU 资源

**CPU**是 Docker 支持和管理的核心资源。ECS 利用 Docker 的 CPU 资源管理能力，并公开通过 ECS 任务定义管理这些资源的能力。ECS 根据*CPU 单位*定义 CPU 资源，其中单个 CPU 核心包含 1,024 个 CPU 单位。在配置 ECS 任务定义时，您需要指定 CPU 保留，这定义了每当 CPU 时间存在争用时将分配给应用程序的 CPU 时间。

请注意，CPU 保留并不限制 ECS 任务可以使用多少 CPU-每个 ECS 任务都可以自由地突发并使用所有可用的 CPU 资源-当 CPU 存在争用时才会应用保留，并且 Docker 会根据每个运行的 ECS 任务的配置保留公平地分配 CPU 时间。

重要的是要理解，每个 CPU 保留都会从给定的 ECS 容器实例的可用 CPU 容量中扣除。例如，如果您的 ECS 容器实例有 2 个 CPU 核心，那就相当于总共有 2,048 个 CPU 单位。如果您运行了配置为 500、600 和 700 CPU 单位的 3 个 ECS 任务，这意味着您的 ECS 容器实例有 2,048 - (500 + 600 + 700)，或 248 个 CPU 单位可用。请注意，每当 ECS 调度程序需要运行新的 ECS 任务时，它将始终确保目标 ECS 容器实例具有足够的 CPU 容量来运行任务。根据前面的例子，如果需要启动一个保留 400 个 CPU 单位的新 ECS 任务，那么剩余 248 个 CPU 单位的 ECS 容器实例将不被考虑，因为它当前没有足够的 CPU 资源可用：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a5a2aea8-a27b-4ae9-baa9-7e542ad03403.png)

分配 CPU 资源

在配置 CPU 保留方面，您已经学会了如何通过 CloudFormation 进行此操作-请参阅第八章*使用 ECS 部署应用程序*中的*使用 CloudFormation 定义 ECS 任务定义*示例，在该示例中，您通过一个名为`Cpu`的属性为 todobackend 容器定义分配了 245 的值。

# 内存资源

内存是另一个通过 Docker 管理的基本资源，其工作方式类似于 CPU，尽管您可以为给定的 ECS 任务保留和限制内存容量，但在管理 CPU 容量时，您只能保留（而不是限制）CPU 资源。当涉及到配置 ECS 任务的内存时，这种额外的限制内存的能力会导致三种情况：

+   **仅内存保留**：这种情况的行为与 CPU 保留的工作方式相同。Docker 将从 ECS 容器实例的可用内存中扣除配置的保留，并在内存有争用时尝试分配这些内存。ECS 将允许 ECS 任务使用 ECS 容器实例支持的最大内存量。内存保留是在 ECS 任务容器定义中使用`MemoryReservation`属性进行配置的。

+   **内存保留+限制**：在这种情况下，内存保留的工作方式与前一种情况相同，但 ECS 任务可以使用的最大内存量受到配置内存限制的限制。一般来说，配置内存保留和内存限制被认为是最佳选择。内存限制是在 ECS 任务容器定义中使用`Memory`属性进行配置的。

+   **仅内存限制**：在这种情况下，ECS 将内存保留和内存限制值视为相同，这意味着 ECS 将从可用的 ECS 容器实例内存中扣除配置的内存限制，并且还将限制内存使用到相同的限制。

配置内存保留和限制是直接的-如果您回顾一下第八章*使用 CloudFormation 定义 ECS 任务定义*部分，您会发现您可以配置`MemoryReservation`属性来配置 395 MB 的保留。如果您想配置内存限制，您还需要使用适当的最大限制值配置`Memory`属性。

# 网络资源

CPU 和内存是您期望您的 ECS 集群控制和管理的典型和明显的资源。另一组不太明显的资源是*网络资源*，可以分为两类：

+   **主机网络端口**：每当您为 ECS 服务配置静态端口映射时，主机网络端口是您需要考虑的资源。原因是静态端口映射使用 ECS 容器实例公开的一个常用端口 - 例如，如果您创建了一个 ECS 任务，其中静态端口映射公开了给定应用程序的端口 80，那么如果端口 80 仍在使用中，您将无法在同一 ECS 容器实例主机上部署 ECS 任务的另一个实例。

+   **主机网络接口**：如果您正在使用 ECS 任务网络，重要的是要了解，该功能目前要求您为每个 ECS 任务实现单个弹性网络接口（ENI）。因为 EC2 实例对每种实例类型支持的 ENI 数量有限制，因此使用 ECS 任务网络配置的 ECS 任务数量将受到 ECS 容器实例可以支持的 ENI 最大数量的限制。

# 计算 ECS 集群容量

在计算 ECS 集群容量之前，您需要清楚地了解哪些资源会影响容量以及如何计算每种资源的当前容量。一旦为每个单独的资源定义了这一点，您就需要在所有资源上应用一个综合计算，这将导致最终计算出当前容量。

计算容量可能看起来是一项相当艰巨的任务，特别是当考虑到不同类型的资源以及它们的行为时：

+   **CPU**：这是您可以使用的最简单的资源，因为每个 CPU 预留只是从集群的可用 CPU 容量中扣除。

+   **内存**：根据内存计算集群的当前容量与 CPU 相同，因为内存预留会从集群的可用内存容量中扣除。根据本章早期讨论，内存预留的配置受到内存限制和内存预留的各种排列组合的影响，但基本上一旦确定了内存预留，计算方式与 CPU 资源相同。

+   静态网络端口：如果您的 ECS 集群需要支持使用静态端口映射的*任何*容器，那么您需要将您的 ECS 容器实例网络端口视为一种资源。例如，如果一个容器应用程序始终在 ECS 容器实例上使用端口 80，那么您只能在每个实例上部署一个容器，而不管该实例可能拥有多少 CPU、内存或其他资源。

+   网络接口：如果您有任何配置为 ECS 任务网络的 ECS 服务或任务，重要的是要了解，您目前只能在一个网络接口上运行一个 ECS 任务。例如，如果您正在运行一个 t2.micro 实例，这意味着您只能在一个实例上运行一个启用了任务网络的 ECS 任务，因为 t2.micro 只能支持一个弹性网络接口用于 ECS 任务网络。

鉴于示例应用程序未使用 ECS 任务网络，并且正在使用动态端口映射进行部署，我们在本章的其余部分只考虑 CPU 和内存资源。如果您对包含静态网络端口的示例解决方案感兴趣，请查看我的《使用亚马逊网络服务进行生产中的 Docker》课程的 Auto Scaling ECS Applications 模块。

挑战在于如何考虑所有 ECS 服务和任务，然后根据所有前述考虑做出决定，决定何时应该扩展或缩减集群中实例的数量。我见过的一种常见且有些天真的方法是独立地处理每个资源，并相应地扩展您的实例。例如，一旦您的集群的内存容量用尽，您就会添加一个新的容器实例，同样，如果您的集群即将耗尽 CPU 容量，也会这样做。如果您纯粹考虑扩展的能力，这种方法是有效的，但是当您想要缩减集群时，它就不起作用了。如果您仅基于当前内存容量来缩减集群，那么在 CPU 容量方面，您可能会过早地缩减，因为如果您从集群中移除一个实例，您的集群可能没有足够的 CPU 容量。

这将使您的集群陷入自动扩展循环中-也就是说，您的集群不断地扩展然后再缩小，这是因为各个资源容量独立地驱动着缩小和扩展的决策，而没有考虑对其他资源的影响。

解决这一挑战的关键在于您需要做出*单一*的扩展或缩小决策，并考虑您集群中*所有*适用的资源。这可能会使整体问题看起来更难解决，但实际上它非常简单。解决方案的关键在于您始终考虑*最坏情况*，并基于此做出决策。例如，如果您的集群中有足够的 CPU 和内存容量，但是所有静态端口映射都在所有集群实例上使用，最坏情况是，如果您缩小集群并删除一个实例，您将无法再支持使用受影响的静态端口映射的当前 ECS 任务。因此，这里的决策是简单的，纯粹基于最坏情况-所有其他情况都被忽略。

# 计算容器容量

在计算集群容量时的一个关键考虑因素是，您需要对资源容量进行归一化计算，以便每个资源的容量可以以一个通用和等效的格式来表达，独立于每个单独资源的具体计量单位。这在做出考虑所有资源的集体决策时至关重要，而这样做的一种自然方式是以当前可用的未分配资源来支持多少额外的 ECS 任务数量来表达资源容量。此外，与最坏情况的主题保持一致，您不需要考虑所有需要支持的不同 ECS 任务-您只需要考虑当前正在计算容量的资源的最坏情况的 ECS 任务（需要最多资源的任务）。

例如，如果您有两个需要分别需要 200 CPU 单位和 400 CPU 单位的 ECS 任务，那么您只需要根据需要 400 CPU 单位的 ECS 任务来计算 CPU 容量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/dd9bfcd2-98df-4a3e-9140-462f6575f3a0.png)

公式中带有有点奇怪的倒立的 A 的表达意思是“对于给定的 taskDefinitions 集合中的每个 taskCpu 值”。

一旦确定了需要支持的最坏情况 ECS 任务，就可以开始计算集群目前可以支持的额外 ECS 任务数量。假设最坏情况的 ECS 任务需要 400 个 CPU 单位，如果现在假设您的集群中有两个实例，每个实例都有 600 个 CPU 单位的空闲容量，这意味着您目前可以支持额外的 2 个 ECS 任务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/43729108-b796-419e-9e92-32de63550246.png)

计算容器容量

这里需要注意的是，您需要按照每个实例的基础进行计算，而不仅仅是在整个集群上进行计算。使用先前的例子，如果您考虑整个集群的空闲 CPU 容量，您有 1,200 个 CPU 单位可用，因此您将计算出三个 ECS 任务的空闲容量，但实际情况是您不能*分割*ECS 任务跨越 2 个实例，因此如果您按照每个实例的空闲容量进行考虑，显然您只能在每个实例上支持一个额外的 ECS 任务，从而得到集群中总共 2 个额外的 ECS 任务的正确总数。

这可以形式化为一个数学方程，如下所示，其中公式右侧的![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/1a7ada8d-43a9-4c10-a5bc-be9a6ea6f917.png)注释表示取*floor*或计算的最低最近整数值，并且代表集群中的一个实例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/f68b3eb6-74a7-4799-94d9-feaa134f7d59.png)

如果您对内存资源重复之前的方法，将计算一个单独的计算，以内存的形式定义集群的当前备用容量。如果我们假设内存的最坏情况 ECS 任务需要 500MB 内存，并且两个实例都有 400MB 可用，显然就内存而言，集群目前没有备用容量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/bbf249ea-73f3-449a-b9bd-5539dcbf50d3.png)

如果现在考虑 CPU 的两个先前计算（目前有两个空闲的 ECS 任务）和内存（目前没有空闲的 ECS 任务），显然最坏情况是内存容量计算为零个空闲的 ECS 任务，可以形式化如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/adf03873-dfc3-4bee-b660-ed1316ce93a2.png)

请注意，虽然我们没有将静态网络端口和网络接口的计算纳入到我们的解决方案中以帮助简化，但一般的方法是相同的 - 计算每个实例的当前容量并求和以获得资源的整体集群容量值，然后将该值纳入整体集群容量的计算中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/72628df2-87bc-4414-a63f-3588709b546c.png)

# 决定何时扩展

在这一点上，我们已经确定您需要评估集群中每个当前资源容量，并以当前集群可以支持的空闲或备用 ECS 任务数量来表达，然后使用最坏情况的计算（最小值）来确定您当前集群的整体容量。一旦您完成了这个计算，您需要决定是否应该扩展集群，或者保持当前集群容量不变。当然，您还需要决定何时缩小集群，但我们将很快单独讨论这个话题。

现在，我们将专注于是否应该扩展集群（即增加容量），因为这是更简单的情景来评估。规则是，至少在当前集群容量小于 1 时，您应该扩展您的集群：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/58383abe-4357-4cb0-924c-090eac36d6f7.png)

换句话说，如果您当前的集群容量不足以支持一个更糟的情况的 ECS 任务，您应该向 ECS 集群添加一个新实例。这是有道理的，因为您正在努力确保您的集群始终具有足够的容量来支持新的 ECS 任务的启动。当然，如果您希望获得更多的空闲容量，您可以将此阈值提高，这可能适用于更动态的环境，其中容器经常启动和关闭。

# 计算空闲主机容量

如果我们现在考虑缩减规模的情况，这就变得有点难以确定了。我们讨论过的备用 ECS 任务容量计算是相关且必要的，但是你需要从这些角度思考：如果你从集群中移除一个 ECS 容器实例，是否有足够的容量来运行所有当前正在运行的 ECS 任务，以及至少还有一个额外的 ECS 任务的备用容量？另一种表达方式是计算集群的*空闲主机容量*——如果集群中有多于 1.0 个主机处于空闲状态，那么你可以安全地缩减集群规模，因为减少一个主机会导致剩余的正值非零容量。请注意，我们指的是整个集群中的空闲主机容量——所以把这看作更像是一个虚拟主机计算，因为你可能不会有完全空闲的主机。这个虚拟主机计算是安全的，因为如果我们从集群中移除一个主机，我们在第十一章*管理 ECS 基础设施生命周期*中介绍的生命周期钩子和 ECS 容器实例排空功能将确保任何运行在要移除的实例上的容器将被迁移到集群中的其他实例上。

还需要了解的是，空闲主机容量必须大于 1.0，而不是等于 1.0，因为你必须有足够的备用容量来运行一个 ECS 任务，否则你将触发一个扩展规模的动作，导致自动扩展的扩展/缩减循环。

要确定当前的空闲主机容量，我们需要了解以下内容：

+   每个不同类型的 ECS 资源对应的每个 ECS 容器实例可以运行的最大 ECS 任务数量（表示为![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/ded39ac8-2846-4051-8be4-ce102e7957d4.png)）。

+   整个集群中每种类型的 ECS 资源的当前空闲容量（表示为![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/848fe089-3774-4825-8c43-ef5ea0ac8539.png)），这是我们在确定是否扩展规模时已经计算过的。

有了这些信息，你可以按照以下方式计算给定资源的空闲主机容量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d6c9883f-b371-4841-9fd4-7e37766be0fc.png)

# 空闲主机容量示例

为了更清楚地说明这一点，让我们通过以下示例来进行计算，如下图所示，假设以下情况：

+   最坏情况下需要 400 个 CPU 单位的 ECS 任务 CPU 要求

+   最坏情况下需要 200 MB 的 ECS 任务内存

+   每个 ECS 容器实例支持最多 1,000 个 CPU 单位和 1,000 MB 内存

+   当前在 ECS 集群中有两个 ECS 容器实例

+   每个 ECS 容器实例目前有 600 个 CPU 单位的空闲容量。使用之前讨论的空闲容量计算，这相当于集群中的当前空闲容量为 2

+   ECS 任务的 CPU 资源，我们将称之为 ![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/fe5db803-ec6f-4713-9618-9e2eac790629.png)。

+   每个 ECS 容器实例目前有 800 MB 的空闲容量。使用之前讨论的空闲容量计算，这相当于集群中的当前空闲容量为 8 个 ECS 任务的内存资源，我们将称之为 ![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d214eb41-2e71-45da-babb-68b187099957.png)：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6f13b876-6d57-4671-8b33-368c9854c33a.png)空闲主机容量

我们可以首先计算 ![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/ab3ad606-7126-402a-8bc2-17b6ac2916d3.png) 值如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a4a2e4f2-fc90-47ca-8260-a8a8a86f925b.png)

对于 CPU，它等于 2，对于内存等于*5*：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/3d4d598d-9e35-4bfb-b62d-e92855b344d6.png)![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/761d58d4-9b6c-46b0-82c9-7781d9f2987c.png)

通过计算这些值并了解集群当前的空闲容量，我们现在可以计算每个资源的空闲主机容量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/e923ae69-d5f0-4d01-b2ca-1943fd040d19.png)![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/d9551f76-8da1-491b-bbba-816942c7297b.png)

以下是如何计算最坏情况下的空闲主机容量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7201e489-d66f-4cae-b766-2b62ae79f69d.png)

在这一点上，鉴于空闲主机容量为 1.0，我们应该*不*缩减集群，因为容量目前*不大于*1。这可能看起来有些反直觉，因为您确实有一个空闲主机，但如果此时删除一个实例，将导致集群的可用 CPU 容量为 0，并且集群将扩展，因为没有空闲的 CPU 容量。

# 实施 ECS 自动扩展解决方案

现在您已经很好地了解了如何计算 ECS 集群容量，以便进行扩展和缩减决策，我们准备实施一个自动扩展解决方案，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/42bafe58-768e-4b70-9a30-b8e072ea6c64.png)

以下提供了在前面的图表中显示的解决方案的步骤：

1.  在计算 ECS 集群容量之前，您需要一个机制来触发容量的计算，最好是在 ECS 容器实例的容量发生变化时触发。这可以通过利用 CloudWatch Events 服务来实现，该服务为包括 ECS 在内的各种 AWS 服务发布事件，并允许您创建*事件规则*，订阅特定事件并使用各种机制（包括 Lambda 函数）处理它们。CloudWatch 事件支持接收有关 ECS 容器实例状态更改的信息，这代表了触发集群容量计算的理想机制，因为 ECS 容器实例的可用资源的任何更改都将触发状态更改事件。

1.  一个负责计算 ECS 集群容量的 Lambda 函数会在每个 ECS 容器实例状态变化事件触发时被触发。

1.  Lambda 函数不会决定自动扩展集群，而是简单地以 CloudWatch 自定义指标的形式发布当前容量，报告当前空闲容器容量和空闲主机容量。

1.  CloudWatch 服务配置了警报，当空闲容器容量或空闲主机容量低于或超过扩展或收缩集群的阈值时，会触发 EC2 自动扩展操作。

1.  EC2 自动扩展服务配置了 EC2 自动扩展策略，这些策略会在 CloudWatch 引发的警报时被调用。

1.  除了配置用于管理 ECS 集群容量的 CloudWatch 警报外，您还可以为每个 ECS 服务配置适当的 CloudWatch 警报，然后触发 AWS 应用自动扩展服务，以扩展或收缩运行您的 ECS 服务的 ECS 任务数量。例如，在前面的图表中，ECS 服务配置了一个应用自动扩展策略，当 ECS 服务的 CPU 利用率超过 50%时，会增加 ECS 任务的数量。

现在让我们实现解决方案的各个组件。

# 为 ECS 配置 CloudWatch 事件

我们需要执行的第一个任务是设置一个 CloudWatch 事件规则，订阅 ECS 容器实例状态变化事件，并配置一个 Lambda 函数作为目标，用于计算 ECS 集群容量。

以下示例演示了如何向 todobackend-aws `stack.yml` CloudFormation 模板添加 CloudWatch 事件规则：

```
...
...
Resources:
  EcsCapacityPermission:
 Type: AWS::Lambda::Permission
 Properties:
 Action: lambda:InvokeFunction
 FunctionName: !Ref EcsCapacityFunction
 Principal: events.amazonaws.com
 SourceArn: !Sub ${EcsCapacityEvents.Arn}
 EcsCapacityEvents:
 Type: AWS::Events::Rule
 Properties:
 Description: !Sub ${AWS::StackName} ECS Events Rule
 EventPattern:
 source:
 - aws.ecs
 detail-type:
 - ECS Container Instance State Change
 detail:
 clusterArn:
 - !Sub ${ApplicationCluster.Arn}
 Targets:
 - Arn: !Sub ${EcsCapacityFunction.Arn}
 Id: !Sub ${AWS::StackName}-ecs-events
  LifecycleHook:
    Type: AWS::AutoScaling::LifecycleHook
...
...
```

`EcsCapacityEvents` 资源定义了事件规则，并包括两个关键属性：

+   `EventPattern`：定义了与此规则匹配事件的模式。所有 CloudWatch 事件都包括 `source`、`detail-type` 和 `detail` 属性，事件模式确保只有与 ECS 事件相关的 ECS 事件（由 `source` 模式 `aws.ecs` 定义）与 ECS 容器实例状态更改（由 `detail-type` 模式定义）与 `ApplicationCluster` 资源（由 `detail` 模式定义）相关的事件将被匹配到规则。

+   `Targets`：定义了事件应该路由到的目标资源。在前面的例子中，你引用了一个名为 `EcsCapacityFunction` 的 Lambda 函数的 ARN，你很快将定义它。

`EcsCapacityPermission` 资源确保 CloudWatch 事件服务有权限调用 `EcsCapacityFunction` Lambda 函数。这是任何调用 Lambda 函数的服务的常见方法，你可以添加一个 Lambda 权限，授予给定 AWS 服务（由 `Principal` 属性定义）对于给定资源（由 `SourceArn` 属性定义）调用 Lambda 函数（`FunctionName` 属性）的能力。

现在，让我们添加引用的 Lambda 函数，以及一个 IAM 角色和 CloudWatch 日志组：

```
...
...
Resources:
  EcsCapacityRole:
 Type: AWS::IAM::Role
 Properties:
 AssumeRolePolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Action:
 - sts:AssumeRole
 Effect: Allow
 Principal:
 Service: lambda.amazonaws.com
 Policies:
 - PolicyName: EcsCapacityPermissions
 PolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Sid: ManageLambdaLogs
 Effect: Allow
 Action:
 - logs:CreateLogStream
 - logs:PutLogEvents
 Resource: !Sub ${EcsCapacityLogGroup.Arn}
 EcsCapacityFunction:
 Type: AWS::Lambda::Function
 DependsOn:
 - EcsCapacityLogGroup
 Properties:
 Role: !Sub ${EcsCapacityRole.Arn}
 FunctionName: !Sub ${AWS::StackName}-ecsCapacity
 Description: !Sub ${AWS::StackName} ECS Capacity Manager
 Code:
 ZipFile: |
 import json
 def handler(event, context):
 print("Received event %s" % json.dumps(event))
 Runtime: python3.6
 MemorySize: 128
 Timeout: 300
 Handler: index.handler
  EcsCapacityLogGroup:
 Type: AWS::Logs::LogGroup
 DeletionPolicy: Delete
 Properties:
 LogGroupName: !Sub /aws/lambda/${AWS::StackName}-ecsCapacity
 RetentionInDays: 7
  EcsCapacityPermission:
    Type: AWS::Lambda::Permission
...
...
```

到目前为止，你应该已经对如何使用 CloudFormation 定义 Lambda 函数有了很好的理解，所以我不会深入描述前面的例子。但是请注意，目前我已经实现了一个基本的函数，它只是简单地打印出接收到的任何事件——我们将使用这个函数来初步了解 ECS 容器实例状态更改事件的结构。

此时，你现在可以使用 `aws cloudformation deploy` 命令部署你的更改：

```
> export AWS_PROFILE=docker-in-aws
> aws cloudformation deploy --template-file stack.yml \
 --stack-name todobackend --parameter-overrides $(cat dev.cfg) \
 --capabilities CAPABILITY_NAMED_IAM
Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga:

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - todobackend
```

部署完成后，你可以通过停止运行在 ECS 集群上的现有 ECS 任务来触发 ECS 容器实例状态更改：

```
> aws ecs list-tasks --cluster todobackend-cluster
{
    "taskArns": [
        "arn:aws:ecs:us-east-1:385605022855:task/5754a076-6f5c-47f1-8e73-c7b229315e31"
    ]
}
> aws ecs stop-task --cluster todobackend-cluster --task 5754a076-6f5c-47f1-8e73-c7b229315e31
```

```
{
    "task": {
        ...
        ...
        "lastStatus": "RUNNING",
        "desiredStatus": "STOPPED",
        ...
        ...
    }
}
```

由于这个 ECS 任务与 ECS 服务相关联，ECS 将自动启动一个新的 ECS 任务，如果你前往 CloudWatch 控制台，选择日志，然后打开用于处理 ECS 容器实例状态更改事件的 Lambda 函数的日志组的最新日志流(`/aws/lambda/todobackend-ecsCapacity`)，你应该会看到一些事件已被记录：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7c264632-6b24-4dd9-b464-645108398b4e.png)

在前面的屏幕截图中，您可以看到在几秒钟内记录了两个事件，这些事件代表您停止 ECS 任务，然后 ECS 自动启动新的 ECS 任务，以确保链接的 ECS 服务达到其配置的期望计数。

您可以看到`source`和`detail-type`属性与您之前配置的事件模式匹配，如果您在第二个事件中继续向下滚动，您应该会找到一个名为`registeredResources`和`remainingResources`的属性，如下例所示：

```
{
  ...
  ...
  "clusterArn":  "arn:aws:ecs:us-east-1:385605022855:cluster/todobackend-cluster",      
  "containerInstanceArn":  "arn:aws:ecs:us-east-1:385605022855:container-instance/d27868d6-79fd-4858-bec6-65720855e0b3",
 "ec2InstanceId":  "i-0d9bd79d19a843216",
  "registeredResources": [             
    { "name":  "CPU", "type":  "INTEGER", "integerValue":  1024 },
    {       "name":  "MEMORY",                 
       "type":  "INTEGER",                 
       "integerValue":  993 },
    { "name":  "PORTS",                 
       "type":  "STRINGSET",                 
       "stringSetValue": ["22","2376","2375","51678","51679"]
    }
  ],
  "remainingResources": [ 
    { 
      "name": "CPU", 
      "type": "INTEGER", 
      "integerValue": 774 
    },
    { 
       "name": "MEMORY", 
       "type": "INTEGER", 
       "integerValue": 593 
    },
    {
       "name": "PORTS", 
       "type": "STRINGSET", 
       "stringSetValue": ["22","2376","2375","51678","51679"]
    }
  ],
  ...
  ...
}
```

`registeredResources`属性定义了分配给实例的总资源，而`remainingResources`指示每个资源的当前剩余数量。因为在前面的示例中，当 ECS 为 todobackend 服务启动新的 ECS 任务时会引发事件，因此从`registeredResources`中扣除了分配给此任务的总 250 个 CPU 单位和 400 MB 内存，然后反映在`remainingResources`属性中。还要注意在示例 12-6 的输出顶部，事件包括其他有用的信息，例如 ECS 集群 ARN 和 ECS 容器实例 ARN 值（由`clusterArn`和`containerInstanceArn`属性指定）。

# 编写计算集群容量的 Lambda 函数

现在，您已经设置了一个 CloudWatch 事件和 Lambda 函数，每当检测到 ECS 容器实例状态变化时就会被调用，您现在可以在 Lambda 函数中实现所需的应用程序代码，以执行适当的 ECS 集群容量计算。

```
...
...
Resources:
  ...
  ...
  EcsCapacityFunction:
    Type: AWS::Lambda::Function
    DependsOn:
      - EcsCapacityLogGroup
    Properties:
      Role: !Sub ${EcsCapacityRole.Arn}
      FunctionName: !Sub ${AWS::StackName}-ecsCapacity
      Description: !Sub ${AWS::StackName} ECS Capacity Manager
      Code:
 ZipFile: |
 import json
          import boto3
          ecs = boto3.client('ecs')
          # Max memory and CPU - you would typically inject these as environment variables
          CONTAINER_MAX_MEMORY = 400
          CONTAINER_MAX_CPU = 250

          # Get current CPU
          def check_cpu(instance):
            return sum(
              resource['integerValue']
              for resource in instance['remainingResources']
              if resource['name'] == 'CPU'
            )
          # Get current memory
          def check_memory(instance):
            return sum(
              resource['integerValue']
              for resource in instance['remainingResources']
              if resource['name'] == 'MEMORY'
            )
          # Lambda entrypoint
          def handler(event, context):
            print("Received event %s" % json.dumps(event))

            # STEP 1 - COLLECT RESOURCE DATA
            cluster = event['detail']['clusterArn']
            # The maximum CPU availble for an idle ECS instance
            instance_max_cpu = next(
              resource['integerValue']
              for resource in event['detail']['registeredResources']
              if resource['name'] == 'CPU')
            # The maximum memory availble for an idle ECS instance
            instance_max_memory = next(
              resource['integerValue']
              for resource in event['detail']['registeredResources']
              if resource['name'] == 'MEMORY')
            # Get current container capacity based upon CPU and memory
            instance_arns = ecs.list_container_instances(
              cluster=cluster
            )['containerInstanceArns']
            instances = [
              instance for instance in ecs.describe_container_instances(
                cluster=cluster,
                containerInstances=instance_arns
              )['containerInstances']
              if instance['status'] == 'ACTIVE'
            ]
            cpu_capacity = 0
            memory_capacity = 0
            for instance in instances:
              cpu_capacity += int(check_cpu(instance)/CONTAINER_MAX_CPU)
              memory_capacity += int(check_memory(instance)/CONTAINER_MAX_MEMORY)
            print("Current container cpu capacity of %s" % cpu_capacity)
            print("Current container memory capacity of %s" % memory_capacity)

            # STEP 2 - CALCULATE OVERALL CONTAINER CAPACITY
            container_capacity = min(cpu_capacity, memory_capacity)
            print("Overall container capacity of %s" % container_capacity)

            # STEP 3 - CALCULATE IDLE HOST COUNT
            idle_hosts = min(
              cpu_capacity / int(instance_max_cpu / CONTAINER_MAX_CPU),
              memory_capacity / int(instance_max_memory / CONTAINER_MAX_MEMORY)
            )
            print("Overall idle host capacity of %s" % idle_hosts)
      Runtime: python3.6
      MemorySize: 128
      Timeout: 300
      Handler: index.handler
...
...
```

在前面的示例中，您首先定义了 ECS 任务的最大 CPU 和最大内存，这是进行各种集群容量计算所必需的，我们使用当前配置的 CPU 和内存设置来支持 todobackend 服务，因为这是我们集群上唯一支持的应用程序。在`handler`函数中，第一步是使用接收到的 CloudWatch 事件收集当前的资源容量数据。该事件包括有关 ECS 容器实例在`registeredResources`属性中的最大容量的详细信息，还包括实例所属的 ECS 集群。该函数首先列出集群中的所有实例，然后使用 ECS 客户端上的`describe_container_instances`调用加载每个实例的详细信息。

对每个实例收集的信息仅限于活动实例，因为您不希望包括可能处于 DRAINING 状态或其他非活动状态的实例的资源。

前面示例中的代码只能在 Python 3.x 环境中正确运行，因此请确保您的 Lambda 函数配置为使用 Python 3.6。

收集有关每个 ECS 容器实例的必要信息后，然后迭代每个实例并计算 CPU 和内存容量。这调用了查询每个实例的`remainingResources`属性的辅助函数，该函数返回每个资源的当前可用容量。每个计算都以您之前定义的最大容器大小来表达，并将它们相加以提供整个集群的 CPU 和内存容量，以供信息目的打印。

下一步是计算整体容器容量，这可以通过取先前计算的资源容量的最小值来轻松计算，这将用于确定您的 ECS 集群何时需要扩展，至少当容器容量低于零时。最后，进行空闲主机容量计算 - 此值将用于确定您的 ECS 集群何时应该缩减，只有当空闲主机容量大于 1.0 时才会发生，如前所述。

# 为计算集群容量添加 IAM 权限

关于前面示例中的代码需要注意的一点是，它需要能够调用 ECS 服务并执行`ListContainerInstances`和`DescribeContainerInstances` API 调用的能力。这意味着您需要向 Lambda 函数 IAM 角色添加适当的 IAM 权限，如下例所示：

```
...
...
Resources:
  ...
  ...
  EcsCapacityRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Action:
              - sts:AssumeRole
            Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
      Policies:
        - PolicyName: EcsCapacityPermissions
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: ListContainerInstances
 Effect: Allow
 Action:
 - ecs:ListContainerInstances
 Resource: !Sub ${ApplicationCluster.Arn}
 - Sid: DescribeContainerInstances
 Effect: Allow
 Action:
 - ecs:DescribeContainerInstances
 Resource: "*"
 Condition:
 ArnEquals:
 ecs:cluster: !Sub ${ApplicationCluster.Arn}
              - Sid: ManageLambdaLogs
                Effect: Allow
                Action:
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: !Sub ${EcsCapacityLogGroup.Arn}
  ...
  ...
```

# 测试集群容量计算

您已经添加了计算集群容量所需的代码，并确保您的 Lambda 函数有适当的权限来查询 ECS 以确定集群中所有 ECS 容器实例的当前容量。您现在可以使用`aws cloudformation deploy`命令部署您的更改，一旦部署完成，您可以通过停止运行在 todobackend ECS 集群中的任何 ECS 任务来再次测试您的 Lambda 函数。

如果您查看 Lambda 函数的 CloudWatch 日志，您应该会看到类似于这里显示的事件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/ce9d382e-863a-4cc2-a461-e0cb3898e99e.png)

请注意，当您停止 ECS 任务（如停止任务事件所表示的），Lambda 函数报告 CPU 容量为 4，内存容量为 2，总体容量为 2，这是计算出的每个资源容量的最小值。

如果您对此进行合理检查，您应该会发现计算是准确和正确的。对于初始事件，因为您停止了 ECS 任务，没有任务在运行，因此可用的 CPU 和内存资源分别为 1,024 个单位和 993 MB（即 t2.micro 实例的容量）。这相当于以下容器容量：

+   CPU 容量 = 1024 / 250 = 4

+   内存容量 = 993 / 400 = 2

当 ECS 自动替换停止的 ECS 任务时，您会看到集群容量下降，因为新的 ECS 任务（具有 250 个 CPU 单位和 400 MB 内存）现在正在消耗资源：

+   CPU 容量 = 1024 - 250 / 250 = 774 / 250 = 3

+   内存容量 = 993 - 400 / 400 = 593 / 400 = 1

最后，您可以看到，当您停止 ECS 任务时，总体空闲主机容量正确计算为 1.0，这是正确的，因为此时集群上没有运行任何 ECS 任务。当 ECS 替换停止的任务时，总体空闲主机容量减少为 0.5，因为 ECS 容器实例现在运行的是最多可以在单个实例上运行的两个 ECS 任务中的一个，就内存资源而言。

# 发布自定义 CloudWatch 指标

此时，我们正在计算确定何时需要扩展或缩小集群的适当指标，并且函数中需要执行的最终任务是发布自定义 CloudWatch 事件指标，我们可以使用这些指标来触发自动扩展策略：

```
...
...
Resources:
  ...
  ...
  EcsCapacityFunction:
    Type: AWS::Lambda::Function
    DependsOn:
      - EcsCapacityLogGroup
    Properties:
      Role: !Sub ${EcsCapacityRole.Arn}
      FunctionName: !Sub ${AWS::StackName}-ecsCapacity
      Description: !Sub ${AWS::StackName} ECS Capacity Manager
      Code:
        ZipFile: |
          import json
          import boto3
          import datetime
          ecs = boto3.client('ecs') cloudwatch = boto3.client('cloudwatch') # Max memory and CPU - you would typically inject these as environment variables
          CONTAINER_MAX_MEMORY = 400
          CONTAINER_MAX_CPU = 250          ...
          ...
          # Lambda entrypoint
          def handler(event, context):
            print("Received event %s" % json.dumps(event))            ...
            ...# STEP 3 - CALCULATE IDLE HOST COUNT            idle_hosts = min(
              cpu_capacity / int(instance_max_cpu / CONTAINER_MAX_CPU),
              memory_capacity / int(instance_max_memory / CONTAINER_MAX_MEMORY)
            )
            print("Overall idle host capacity of %s" % idle_hosts)

 # STEP 4 - PUBLISH CLOUDWATCH METRICS
 cloudwatch.put_metric_data(
 Namespace='AWS/ECS',
 MetricData=[
              {
                'MetricName': 'ContainerCapacity',
                'Dimensions': [{
                  'Name': 'ClusterName',
                  'Value': cluster.split('/')[-1]
                }],
                'Timestamp': datetime.datetime.utcnow(),
                'Value': container_capacity
              }, 
              {
 'MetricName': 'IdleHostCapacity',
 'Dimensions': [{
 'Name': 'ClusterName',
 'Value': cluster.split('/')[-1]
 }],
 'Timestamp': datetime.datetime.utcnow(),
 'Value': idle_hosts
 }
            ])
      Runtime: python3.6
      MemorySize: 128
      Timeout: 300
      Handler: index.handler
...
...
```

在前面的示例中，您使用 CloudWatch 客户端的`put_metric_data`函数来发布 AWS/ECS 命名空间中的`ContainerCapacity`和`IdleHostCapacity`自定义指标。这些指标基于 ECS 集群进行维度化，由 ClusterName 维度名称指定，并且仅限于 todobackend ECS 集群。

确保 Lambda 函数正确运行的最后一个配置任务是授予函数权限以发布 CloudWatch 指标。这可以通过在先前示例中创建的`EcsCapacityRole`中添加适当的 IAM 权限来实现：

```
...
...
Resources:
  ...
  ...
  EcsCapacityRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Action:
              - sts:AssumeRole
            Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
      Policies:
        - PolicyName: EcsCapacityPermissions
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: PublishCloudwatchMetrics
 Effect: Allow
 Action:
 - cloudwatch:putMetricData
 Resource: "*"
              - Sid: ListContainerInstances
                Effect: Allow
                Action:
                  - ecs:ListContainerInstances
                Resource: !Sub ${ApplicationCluster.Arn}
              - Sid: DescribeContainerInstances
                Effect: Allow
                Action:
                  - ecs:DescribeContainerInstances
                Resource: "*"
                Condition:
                  ArnEquals:
                    ecs:cluster: !Sub ${ApplicationCluster.Arn}
              - Sid: ManageLambdaLogs
                Effect: Allow
                Action:
                - logs:CreateLogStream
                - logs:PutLogEvents
                Resource: !Sub ${EcsCapacityLogGroup.Arn}
  ...
  ...
```

如果您现在使用`aws cloudformation deploy`命令部署更改，然后停止运行的 ECS 任务，在切换到 CloudWatch 控制台后，您应该能够看到与您的 ECS 集群相关的新指标被发布。如果您从左侧菜单中选择**指标**，然后在**所有指标**下选择**ECS > ClusterName**，您应该能够看到您的自定义指标（`ContainerCapacity`和`IdleHostCapacity`）。以下截图显示了这些指标基于一分钟内收集的最大值进行绘制。在图表的 12:49 处，您可以看到当您停止 ECS 任务时，`ContainerCapacity`和`IdleHostCapacity`指标都增加了，然后一旦 ECS 启动了新的 ECS 任务，这两个指标的值都减少了，因为新的 ECS 任务从您的集群中分配了资源：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/59c87186-8313-4217-ba03-df4041c220e8.png)

# 为集群容量管理创建 CloudWatch 警报。

现在，您可以在 ECS 集群中计算和发布 ECS 集群容量指标，每当 ECS 集群中的 ECS 容器实例状态发生变化时。整体解决方案的下一步是实施 CloudWatch 警报，这将在指标超过或低于与集群容量相关的指定阈值时触发自动扩展操作。

以下代码演示了向 todobackend 堆栈添加两个 CloudWatch 警报：

```
...
...
Resources:
  ...
  ...
 ContainerCapacityAlarm:
 Type: AWS::CloudWatch::Alarm
 Properties:
 AlarmDescription: ECS Cluster Container Free Capacity
 AlarmActions:
        - !Ref ApplicationAutoscalingScaleOutPolicy
 Namespace: AWS/ECS
 Dimensions:
 - Name: ClusterName
 Value: !Ref ApplicationCluster
 MetricName: ContainerCapacity
 Statistic: Minimum
 Period: 60
 EvaluationPeriods: 1
 Threshold: 1
 ComparisonOperator: LessThanThreshold
 TreatMissingData: ignore
 IdleHostCapacityAlarm:
 Type: AWS::CloudWatch::Alarm
 Properties:
 AlarmDescription: ECS Cluster Container Free Capacity
 AlarmActions:
        - !Ref ApplicationAutoscalingScaleInPolicy
 Namespace: AWS/ECS
 Dimensions:
 - Name: ClusterName
 Value: !Ref ApplicationCluster
 MetricName: IdleHostCapacity
 Statistic: Maximum
 Period: 60
 EvaluationPeriods: 1
 Threshold: 1
 ComparisonOperator: GreaterThanThreshold
 TreatMissingData: ignore
  ...
  ...
```

在前面的示例中，您添加了两个 CloudWatch 警报-一个`ContainerCapacityAlarm`，每当容器容量低于 1 时将用于触发扩展操作，以及一个`IdleHostCapacityAlarm`，每当空闲主机容量大于 1 时将用于触发缩减操作。每个警报的各种属性在此处有进一步的描述：

+   `AlarmActions`：定义应该采取的操作，如果警报违反其配置的条件。在这里，我们引用了我们即将定义的 EC2 自动扩展策略资源，这些资源在引发警报时会触发适当的自动扩展扩展或缩减操作。

+   `Namespace`：定义警报所关联的指标的命名空间。

+   `Dimensions`：定义指标与给定命名空间内的资源的关系的上下文。在前面的示例中，上下文配置为我们堆栈内的 ECS 集群。

+   `MetricName`：定义指标的名称。在这里，我们指定了在上一节中发布的每个自定义指标的名称。

+   `统计`：定义应该评估的指标的统计数据。这实际上是一个非常重要的参数，在容器容量警报的情况下，设置最大值确保短暂指标不会不必要地触发警报，假设在每个评估周期内至少有 1 个值超过配置的阈值。对于空闲主机容量警报也是如此，但方向相反。

+   `Period`、`EvaluationPeriods`、`Threshold`和`ComparisonOperator`：这些定义了指标必须在配置的阈值和比较运算符的范围之外的时间范围。如果超出了这些范围，将会触发警报。

+   `TreatMissingData`：此设置定义了如何处理缺少的指标数据。在我们的用例中，由于我们仅在 ECS 容器实例状态更改时发布指标数据，因此将值设置为`ignore`可以确保我们不会将缺失的数据视为有问题的指示。

# 创建 EC2 自动扩展策略

现在，您需要创建您在每个 CloudWatch 警报资源中引用的 EC2 自动扩展策略资源。

以下示例演示了向 todobackend 堆栈添加扩展和缩减策略：

```
...
...
Resources:
  ...
  ...
 ApplicationAutoscalingScaleOutPolicy:
    Type: AWS::AutoScaling::ScalingPolicy
    Properties:
      PolicyType: SimpleScaling
      AdjustmentType: ChangeInCapacity
      ScalingAdjustment: 1
      AutoScalingGroupName: !Ref ApplicationAutoscaling
      Cooldown: 600
  ApplicationAutoscalingScaleInPolicy:
    Type: AWS::AutoScaling::ScalingPolicy
    Properties:
      PolicyType: SimpleScaling
      AdjustmentType: ChangeInCapacity
      ScalingAdjustment: -1
      AutoScalingGroupName: !Ref ApplicationAutoscaling
      Cooldown: 600
  ...
  ...
  ApplicationAutoscaling:
    Type: AWS::AutoScaling::AutoScalingGroup
    DependsOn:
      - DmesgLogGroup
      - MessagesLogGroup
      - DockerLogGroup
      - EcsInitLogGroup
      - EcsAgentLogGroup
    CreationPolicy:
      ResourceSignal:
 Count: 1
        Timeout: PT15M
    UpdatePolicy:
      AutoScalingRollingUpdate:
        SuspendProcesses:
 - HealthCheck
 - ReplaceUnhealthy
 - AZRebalance
 - AlarmNotification
 - ScheduledActions        MinInstancesInService: 1
        MinSuccessfulInstancesPercent: 100
        WaitOnResourceSignals: "true"
        PauseTime: PT15M
    Properties:
      LaunchConfigurationName: !Ref ApplicationAutoscalingLaunchConfiguration
      MinSize: 0
      MaxSize: 4
 DesiredCapacity: 1        ...
        ...

```

在上面的示例中，您定义了两种`SimpleScaling`类型的自动扩展策略，它代表了您可以实现的最简单的自动扩展形式。各种自动扩展类型的讨论超出了本书的范围，但如果您对了解更多可用选项感兴趣，可以参考[`docs.aws.amazon.com/autoscaling/ec2/userguide/as-scale-based-on-demand.html`](https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scale-based-on-demand.html)。`AdjustmentType`和`ScalingAdjustment`属性配置为增加或减少自动扩展组的一个实例的大小，而`Cooldown`属性提供了一种机制，以确保在指定的持续时间内禁用进一步的自动扩展操作，这可以帮助避免集群频繁地扩展和缩减。

请注意，`ApplicationAutoscaling`的`UpdatePolicy`设置已更新以包括`SuspendProcesses`参数，该参数配置 CloudFormation 在进行自动扩展滚动更新时禁用某些操作过程。这特别是在滚动更新期间禁用自动扩展操作很重要，因为您不希望自动扩展操作干扰由 CloudFormation 编排的滚动更新。最后，我们还将`ApplicationAutoscaling`资源上的各种计数设置为固定值 1，因为自动扩展现在将管理我们的 ECS 集群的大小。

# 测试 ECS 集群容量管理

现在，我们已经拥有了计算 ECS 集群容量、发布指标和触发警报的所有组件，这将调用自动扩展操作，让我们部署我们的更改并测试解决方案是否按预期工作。

# 测试扩展

人为触发扩展操作，我们需要在`dev.cfg`配置文件中将`ApplicationDesiredCount`输入参数设置为 2，这将增加我们的 ECS 服务的 ECS 任务计数为 2，并导致 ECS 集群中的单个 ECS 容器实例不再具有足够的资源来支持任何进一步的附加容器：

```
ApplicationDesiredCount=2
ApplicationImageId=ami-ec957491
ApplicationImageTag=5fdbe62
ApplicationSubnets=subnet-a5d3ecee,subnet-324e246f
VpcId=vpc-f8233a80
```

此配置更改应导致`ContainerCapacity`指标下降到配置的警报阈值`1`以下，我们可以通过运行`aws cloudformation deploy`命令将更改部署到 CloudFormation 来进行测试。

部署完成后，如果您浏览到 CloudWatch 控制台并从左侧菜单中选择警报，您应该会看到您的容器容量警报进入警报状态（可能需要几分钟），如前所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/3aedb0f1-0201-435f-b6b0-557d67d1ed07.png)

您可以在操作详细信息中看到 CloudWatch 警报已触发应用程序自动扩展的扩展策略，并且在左侧的图表中注意到，这是因为容器容量由于单个 ECS 容器实例上运行的 ECS 任务增加而下降到 0。

如果您现在导航到 EC2 控制台，从左侧菜单中选择**自动扩展组**，然后选择 todobackend 自动扩展组的**活动历史**选项卡，您会看到自动扩展组中当前实例计数为`2`，并且由于容器容量警报转换为警报状态而启动了一个新的 EC2 实例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/f9681a0f-4867-4e7c-adca-a75bc78fc5d7.png)

一旦新的 ECS 容器实例被添加到 ECS 集群中，新的容量计算将会发生，如果您切换回 CloudWatch 控制台，您应该看到 ContainerCapacity 警报最终转换为 OK 状态，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4ae43aef-c5b7-4dc5-98b3-2fe6a3b832eb.png)

在右下角的图表中，您可以看到添加一个新的 ECS 容器实例的效果，这将把容器容量从`0`增加到`2`，将容器容量警报置为 OK 状态。

# 测试缩减规模

现在您已经成功测试了 ECS 集群容量管理解决方案的扩展行为，让我们现在通过在`dev.cfg`文件中将`ApplicationDesiredCount`减少到 1，并运行`aws cloudformation deploy`命令来部署修改后的计数，人为地触发缩减行为：

```
ApplicationDesiredCount=1
ApplicationImageId=ami-ec957491
ApplicationImageTag=5fdbe62
ApplicationSubnets=subnet-a5d3ecee,subnet-324e246f
VpcId=vpc-f8233a80
```

一旦这个改变被部署，您应该在 CloudWatch 控制台上看到空闲主机容量警报在几分钟后变为 ALARM 状态：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4121b365-3f94-4ed5-ba0e-e95ceb74cc1f.png)

在前面的截图中，空闲主机容量从 1.0 增加到 1.5，因为现在我们只有一个正在运行的 ECS 任务和两个 ECS 容器实例在集群中。这触发了配置的应用程序自动缩放缩减策略，它将减少 ECS 集群容量到一个 ECS 容器实例，并最终空闲主机容量警报将转换为 OK 状态。

# 配置 AWS 应用自动扩展服务

我们现在已经有了一个 ECS 集群容量管理解决方案，它将自动扩展和缩减您的 ECS 集群，当新的 ECS 任务在您的 ECS 集群中出现和消失时。到目前为止，我们通过手动增加 todobackend ECS 服务的任务数量来人为测试这一点，然而在您的真实应用中，您通常会使用 AWS 应用自动扩展服务，根据应用程序最合适的指标动态地扩展和缩减您的 ECS 服务。

ECS 集群容量的另一个影响因素是部署新应用程序，以 ECS 任务定义更改的形式应用到 ECS 服务。ECS 的滚动更新机制通常会暂时增加 ECS 任务数量，这可能会导致 ECS 集群在短时间内扩展，然后再缩小。您可以通过调整容器容量在降低到配置的最小阈值之前可以持续的时间来调整此行为，并且还可以增加必须始终可用的最小容器容量阈值。这种方法可以在集群中建立更多的备用容量，从而使您能够对容量变化做出较少激进的响应，并吸收滚动部署引起的瞬时容量波动。

AWS 应用自动扩展比 EC2 自动扩展更复杂，至少需要几个组件：

+   **CloudWatch 警报**：这定义了您感兴趣的指标，并在应该扩展或缩小时触发。

+   **自动扩展目标**：这定义了应用程序自动扩展将应用于的目标组件。对于我们的场景，这将被配置为 todobackend ECS 服务。

+   **自动扩展 IAM 角色**：您必须创建一个 IAM 角色，授予 AWS 应用自动扩展服务权限来管理您的 CloudWatch 警报，读取您的应用自动扩展策略，并修改您的 ECS 服务以增加或减少 ECS 服务任务数量。

+   **扩展和缩小策略**：这些定义了与扩展 ECS 服务和缩小 ECS 服务相关的行为。

# 配置 CloudWatch 警报

让我们首先通过在`stack.yml`模板中添加一个 CloudWatch 警报来触发应用程序自动扩展：

```
...
...
Resources:
  ApplicationServiceLowCpuAlarm:
 Type: AWS::CloudWatch::Alarm
 Properties:
 AlarmActions:
 - !Ref ApplicationServiceAutoscalingScaleInPolicy
 AlarmDescription: Todobackend Service Low CPU 
 Namespace: AWS/ECS
 Dimensions:
 - Name: ClusterName
 Value: !Ref ApplicationCluster
 - Name: ServiceName
 Value: !Sub ${ApplicationService.Name}
 MetricName: CPUUtilization
 Statistic: Average
 Period: 60
 EvaluationPeriods: 3
 Threshold: 20
 ComparisonOperator: LessThanThreshold
 ApplicationServiceHighCpuAlarm:
 Type: AWS::CloudWatch::Alarm
 Properties:
 AlarmActions:
 - !Ref ApplicationServiceAutoscalingScaleOutPolicy
 AlarmDescription: Todobackend Service High CPU 
 Namespace: AWS/ECS
 Dimensions:
 - Name: ClusterName
 Value: !Ref ApplicationCluster
 - Name: ServiceName
 Value: !Sub ${ApplicationService.Name}
 MetricName: CPUUtilization
 Statistic: Average
 Period: 60
 EvaluationPeriods: 3
 Threshold: 40
 ComparisonOperator: GreaterThanThreshold
  ...
  ...
```

在前面的示例中，为低 CPU 和高 CPU 条件创建了警报，并将其维度设置为运行在 todobackend ECS 集群上的 todobackend ECS 服务。当 ECS 服务的平均 CPU 利用率在 3 分钟（3 x 60 秒）的时间内大于 40%时，将触发高 CPU 警报，当平均 CPU 利用率在 3 分钟内低于 20%时，将触发低 CPU 警报。在每种情况下，都配置了警报操作，引用了我们即将创建的扩展和缩小策略资源。

# 定义自动扩展目标

AWS 应用自动缩放要求您定义自动缩放目标，这是您需要扩展或缩小的资源。对于 ECS 的用例，这被定义为 ECS 服务，如前面的示例所示：

```
...
...
Resources:
 ApplicationServiceAutoscalingTarget:
 Type: AWS::ApplicationAutoScaling::ScalableTarget
 Properties:
 ServiceNamespace: ecs
 ResourceId: !Sub service/${ApplicationCluster}/${ApplicationService.Name}
 ScalableDimension: ecs:service:DesiredCount
 MinCapacity: 1
 MaxCapacity: 4
 RoleARN: !Sub ${ApplicationServiceAutoscalingRole.Arn}
  ...
  ...
```

在前面的示例中，您为自动缩放目标定义了以下属性：

+   `ServiceNamespace`：定义目标 AWS 服务的命名空间。当针对 ECS 服务时，将其设置为 `ecs`。

+   `ResourceId`：与目标关联的资源的标识符。对于 ECS，这是以 `service/<ecs-cluster-name>/<ecs-service-name>` 格式定义的。

+   `ScalableDimension`：指定可以扩展的目标资源类型的属性。在 ECS 服务的情况下，这是 `DesiredCount` 属性，其定义为 `ecs:service:DesiredCount`。

+   `MinCapacity` 和 `MaxCapacity`：期望的 ECS 服务计数可以扩展的最小和最大边界。

+   `RoleARN`：应用自动缩放服务将用于扩展和缩小目标的 IAM 角色的 ARN。在前面的示例中，您引用了下一节中将创建的 IAM 资源。

有关上述每个属性的更多详细信息，您可以参考 [应用自动缩放 API 参考](https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html)。

# 创建自动缩放 IAM 角色

在应用自动缩放目标的资源定义中，您引用了应用自动缩放服务将扮演的 IAM 角色。以下示例定义了此 IAM 角色以及应用自动缩放服务所需的权限：

```
...
...
Resources:
  ApplicationServiceAutoscalingRole:
 Type: AWS::IAM::Role
 Properties:
 AssumeRolePolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Action:
 - sts:AssumeRole
 Effect: Allow
 Principal:
 Service: application-autoscaling.amazonaws.com
 Policies:
 - PolicyName: AutoscalingPermissions
 PolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Effect: Allow
 Action:
 - application-autoscaling:DescribeScalableTargets
 - application-autoscaling:DescribeScalingActivities
 - application-autoscaling:DescribeScalingPolicies
 - cloudwatch:DescribeAlarms
 - cloudwatch:PutMetricAlarm
 - ecs:DescribeServices
 - ecs:UpdateService
 Resource: "*"
  ApplicationServiceAutoscalingTarget:
    Type: AWS::ApplicationAutoScaling::ScalableTarget
  ...
  ...
```

您可以看到应用自动缩放服务需要与应用自动缩放服务本身关联的一些读取权限，以及管理 CloudWatch 警报的能力，并且必须能够更新 ECS 服务以管理 ECS 服务的期望计数。请注意，您必须在 `AssumeRolePolicyDocument` 部分中将主体指定为 `application-autoscaling.amazonaws.com`，这允许应用自动缩放服务扮演该角色。

# 配置扩展和缩小策略

配置应用自动缩放时的最后一个任务是添加扩展和缩小策略：

```
...
...
Resources:
  ApplicationServiceAutoscalingScaleInPolicy:
 Type: AWS::ApplicationAutoScaling::ScalingPolicy
 Properties:
 PolicyName: ScaleIn
 PolicyType: StepScaling
 ScalingTargetId: !Ref ApplicationServiceAutoscalingTarget
 StepScalingPolicyConfiguration:
 AdjustmentType: ChangeInCapacity
 Cooldown: 360
 MetricAggregationType: Average
 StepAdjustments:
 - ScalingAdjustment: -1
 MetricIntervalUpperBound: 0
 ApplicationServiceAutoscalingScaleOutPolicy:
Type: AWS::ApplicationAutoScaling::ScalingPolicy
 Properties:
 PolicyName: ScaleOut
 PolicyType: StepScaling
 ScalingTargetId: !Ref ApplicationServiceAutoscalingTarget
 StepScalingPolicyConfiguration:
 AdjustmentType: ChangeInCapacity
 Cooldown: 360
 MetricAggregationType: Average
 StepAdjustments:
 - ScalingAdjustment: 1
 MetricIntervalLowerBound: 0
```

```
ApplicationServiceAutoscalingRole:
    Type: AWS::IAM::Role
  ...
  ...
```

在这里，您定义了扩展和缩小策略，确保资源名称与您之前引用的那些匹配，当您配置用于触发策略的 CloudWatch 警报时。`PolicyType`参数指定您正在配置 Step-Scaling 策略，它们的工作方式类似于您之前定义的 EC2 自动缩放策略，并允许您以增量步骤进行缩放。其余属性都相当容易理解，尽管`StepAdjustments`属性确实需要进一步描述。

`ScalingAdjustment`指示每次缩放时您将增加或减少 ECS 服务计数的数量，而`MetricIntervalLowerBound`和`MetricIntervalUpperBound`属性允许您在超出警报阈值时定义额外的边界，以便您的自动缩放操作应用。

在上面的示例中显示的配置是，每当 CPU 利用率超过或低于配置的 CloudWatch 警报阈值时，应用程序自动缩放将始终被调用。这是因为未配置的上限和下限默认为无穷大或负无穷大，因此在警报阈值和无穷大/负无穷大之间的任何指标值都将触发警报。为了进一步澄清指标间隔边界的上下文，如果您改为配置`MetricIntervalLowerBound`值为 10 和`MetricIntervalUpperBound`为 30，当超过 CloudWatch 警报阈值（当前配置为 40%的 CPU 利用率）时，自动缩放操作将仅在 50%利用率（阈值+`MetricIntervalLowerBound`或 40+10=50）和 70%利用率（`阈值`+`MetricIntervalUpperBound`或 40+30=70%）之间应用。

# 部署应用程序自动缩放

在这一点上，您现在已经准备部署您的 ECS 应用程序自动缩放解决方案。运行`aws cloudformation deploy`命令后，如果您浏览到 ECS 控制台，选择 todobackend 集群和 todobackend ECS 服务，在自动缩放选项卡上，您应该看到您的新应用程序自动缩放配置已经就位：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b959b6fd-e570-4d8f-99d1-2d243f9b4f1d.png)

现在，每当您的 ECS 服务的 CPU 利用率超过 40%（在所有 ECS 任务中平均），您的 ECS 服务的期望计数将增加一个。只要 CPU 利用率超过 40%，这将持续下去，最多增加到 4 个任务，根据前面示例的配置，每个自动扩展操作之间将应用 360 秒的冷却期。

在 ECS 服务级别上，您无需担心底层 ECS 集群资源，因为您的 ECS 集群容量管理解决方案确保集群中始终有足够的空闲容量来容纳额外的 ECS 任务。这意味着您现在可以根据每个 ECS 服务的特定性能特征独立扩展每个 ECS 服务，并强调了了解每个应用程序的最佳 ECS 任务资源分配的重要性。

# 总结

在本章中，您创建了一个全面的自动扩展解决方案，可以让您根据应用程序负载和客户需求自动扩展您的 ECS 服务和应用程序，同时确保底层 ECS 集群有足够的资源来部署新的 ECS 任务。

首先，您了解了关键的 ECS 资源，包括 CPU、内存、网络端口和网络接口，以及 ECS 如何分配这些资源。在管理 ECS 集群容量时，这些资源决定了 ECS 容器实例是否能够运行特定的 ECS 任务，因此您必须了解每种资源的消耗情况至关重要。

接下来，您实现了一个 ECS 集群容量管理解决方案，该解决方案在 ECS 容器实例状态发生变化时计算 ECS 集群容量。ECS 通过 CloudWatch 事件发布这些状态更改，您创建了一个 CloudWatch 事件规则，触发一个 Lambda 函数来计算当前的集群容量。该函数计算了两个关键指标——容器容量，表示集群当前可以支持的额外容器或 ECS 任务的数量，以及空闲主机容量，定义了整个集群中当前有多少“虚拟”主机处于空闲状态。容器容量用于扩展您的 ECS 集群，在容器容量低于 1 时添加额外的 ECS 容器实例，这意味着集群不再具有足够的资源来部署额外的 ECS 任务。空闲主机容量用于缩小您的 ECS 集群，在空闲主机容量大于 1.0 时移除 ECS 容器实例，这意味着您可以安全地移除一个 ECS 容器实例，并仍然有能力部署新的 ECS 任务。

我们讨论的一个关键概念是始终要为所有资源的最坏情况共同进行这些计算的要求，这确保了当您拥有某种类型资源的充足空闲容量时，您永远不会进行缩小，但可能对另一种类型资源的容量较低。

最后，您学会了如何配置 AWS 应用程序自动扩展服务来扩展和缩小您的 ECS 服务。在这里，您根据应用程序特定的适当指标来扩展单个 ECS 服务，因为您是在单个 ECS 服务的上下文中进行扩展，所以在这个级别进行自动扩展是简单定义和理解的。扩展您的 ECS 服务最终是驱动您整体 ECS 集群容量变化的原因，而您实现的 ECS 集群容量管理解决方案负责处理这一点，使您能够自动扩展您的 ECS 服务，而无需担心对底层 ECS 集群的影响。

在下一章中，您将学习如何将您的 ECS 应用程序持续交付到 AWS，将我们在前几章中讨论过的所有功能都纳入其中。这将使您能够以完全自动化的方式部署最新的应用程序更改，减少运营开销，并为开发团队提供快速反馈。

# 问题

1.  真/假：当您使用 ECS 并部署自己的 ECS 容器实例时，ECS 会自动为您扩展集群。

1.  您使用哪个 AWS 服务来扩展您的 ECS 集群？

1.  您使用哪个 AWS 服务来扩展您的 ECS 服务？

1.  您的应用程序需要最少 300MB，最多 1GB 的内存才能运行。您会在 ECS 任务定义中配置哪些参数来支持这个配置？

1.  您将 3 个不同的 ECS 任务部署到单个实例 ECS 集群中，每个任务运行不同的应用程序，并配置每个 ECS 任务保留 10 个 CPU 单位。在繁忙时期，其中一个 ECS 任务占用了 CPU，减慢了其他 ECS 任务的速度。假设 ECS 容器实例的容量为 1,000 个 CPU 单位，您可以采取什么措施来避免一个 ECS 任务占用 CPU？

1.  真/假：如果您只为 ECS 任务使用动态端口映射，您就不需要担心网络端口资源。

1.  您在 AWS 部署了一个支持总共四个网络接口的实例。假设所有 ECS 任务都使用 ECS 任务网络，那么实例的容量是多少？

1.  在 EC2 自动缩放组中，何时应该禁用自动缩放？你会如何做？

1.  您的 ECS 集群目前有 2 个 ECS 容器实例，每个实例有 500 个 CPU 单位和 500MB 的内存剩余容量。您只向集群部署了一种应用程序，目前有两个 ECS 任务正在运行。假设 ECS 任务需要 500 个 CPU 单位、500MB 的内存，并且静态端口映射到 TCP 端口 80，那么集群当前的整体剩余容量是多少个 ECS 任务？

1.  您的 ECS 集群需要支持 3 个不同的 ECS 任务，分别需要 300MB、400MB 和 500MB 的内存。如果您的每个 ECS 容器实例都有 2GB 的内存，那么在进行 ECS 集群容量计算时，您会将每个 ECS 容器实例的最大容器数量计算为多少？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   ECS 服务自动缩放：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/service-auto-scaling.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-auto-scaling.html)

+   EC2 自动扩展用户指南：[`docs.aws.amazon.com/autoscaling/ec2/userguide/what-is-amazon-ec2-auto-scaling.html`](https://docs.aws.amazon.com/autoscaling/ec2/userguide/what-is-amazon-ec2-auto-scaling.html)

+   EC2 自动扩展策略类型：[`docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html`](https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html)

+   自动扩展组滚动更新的推荐最佳实践：[`aws.amazon.com/premiumsupport/knowledge-center/auto-scaling-group-rolling-updates/`](https://aws.amazon.com/premiumsupport/knowledge-center/auto-scaling-group-rolling-updates/)

+   应用自动扩展用户指南：[`docs.aws.amazon.com/autoscaling/application/userguide/what-is-application-auto-scaling.html`](https://docs.aws.amazon.com/autoscaling/application/userguide/what-is-application-auto-scaling.html)

+   任务定义参数参考（请参阅`cpu`、`memory`和`memoryReservation`参数）：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definitions`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definitions)

+   CloudFormation CloudWatch 事件规则资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html)

+   CloudFormation CloudWatch 警报资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cw-alarm.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cw-alarm.html)

+   CloudFormation EC2 自动扩展策略资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html)

+   CloudFormation 应用自动扩展可扩展目标资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalabletarget.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalabletarget.html)

+   CloudFormation 应用程序自动扩展策略资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalingpolicy.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalingpolicy.html)
