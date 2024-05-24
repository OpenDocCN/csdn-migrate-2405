# Docker AWS 教程（四）

> 原文：[`zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5`](https://zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 ECS 部署应用程序

在上一章中，您学习了如何使用 EC2 自动扩展组在 AWS 中配置和部署 ECS 集群，本章的目标是使用 CloudFormation 将 ECS 应用程序部署到您新建的 ECS 集群。

您将首先开始学习如何定义和部署通常在生产环境中 ECS 应用程序中所需的各种支持资源。这些资源包括创建应用程序数据库以存储应用程序的数据，部署应用程序负载均衡器以服务和负载均衡对应用程序的请求，以及配置其他资源，例如 IAM 角色和安全组，以控制对应用程序的访问和从应用程序的访问。

有了这些支持资源，您将继续创建 ECS 任务定义，定义容器的运行时配置，然后配置 ECS 服务，将 ECS 任务定义部署到 ECS 集群，并与应用程序负载均衡器集成，以管理滚动部署等功能。最后，您将学习如何创建 CloudFormation 自定义资源，执行自定义的配置任务，例如运行数据库迁移，为您提供基于 AWS CloudFormation 的完整应用程序部署框架。

将涵盖以下主题：

+   使用 RDS 创建应用程序数据库

+   配置应用程序负载均衡器

+   创建 ECS 任务定义

+   部署 ECS 服务

+   ECS 滚动部署

+   创建 CloudFormation 自定义资源

# 技术要求

以下列出了完成本章所需的技术要求：

+   AWS 账户的管理员访问权限

+   本地 AWS 配置文件按第三章的说明配置

+   AWS CLI

+   本章将继续自第七章开始，因此需要您成功完成那里定义的所有配置任务

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch8`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch8)[.](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch4)

查看以下视频以查看代码的实际操作：

[`bit.ly/2Mx8wHX`](http://bit.ly/2Mx8wHX)

# 使用 RDS 创建应用程序数据库

示例 todobackend 应用程序包括一个 MySQL 数据库，用于持久化通过应用程序 API 创建的待办事项。当您在第一章首次设置和运行示例应用程序时，您使用 Docker 容器提供应用程序数据库，但是在生产级环境中，通常认为最佳做法是在专门为数据库和数据访问操作进行了优化的专用机器上运行数据库和其他提供持久性存储的服务。AWS 中的一个这样的服务是关系数据库服务（RDS），它提供了专用的托管实例，针对提供流行的关系数据库引擎进行了优化，包括 MySQL、Postgres、SQL Server 和 Oracle。RDS 是一个非常成熟和强大的服务，非常常用于支持在 AWS 中运行的 ECS 和其他应用程序的数据库需求。

可以使用 CloudFormation 配置 RDS 实例。要开始，让我们在您的 todobackend CloudFormation 模板中定义一个名为`ApplicationDatabase`的新资源，其资源类型为`AWS::RDS::DBInstance`，如下例所示：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: Todobackend Application

Parameters:
  ApplicationDesiredCount:
    Type: Number
    Description: Desired EC2 instance count
  ApplicationImageId:
    Type: String
    Description: ECS Amazon Machine Image (AMI) ID
  ApplicationSubnets:
    Type: List<AWS::EC2::Subnet::Id>
    Description: Target subnets for EC2 instances
  DatabasePassword:
 Type: String
 Description: Database password
 NoEcho: "true"
  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: Target VPC

Resources:
  ApplicationDatabase:
 Type: AWS::RDS::DBInstance
 Properties:
 Engine: MySQL
 EngineVersion: 5.7
 DBInstanceClass: db.t2.micro
 AllocatedStorage: 10
 StorageType: gp2
 MasterUsername: todobackend
 MasterUserPassword: !Ref DatabasePassword
 DBName: todobackend
 VPCSecurityGroups:
 - !Ref ApplicationDatabaseSecurityGroup
 DBSubnetGroupName: !Ref ApplicationDatabaseSubnetGroup
 MultiAZ: "false"
 AvailabilityZone: !Sub ${AWS::Region}a
      Tags:
        - Key: Name
          Value: !Sub ${AWS::StackName}-db  ApplicationAutoscalingSecurityGroup:
    Type: AWS::EC2::SecurityGroup
...
...
```

创建 RDS 资源

前面示例中的配置被认为是定义 RDS 实例的最小配置，如下所述：

+   `Engine`和`EngineVersion`：数据库引擎，在本例中是 MySQL，以及要部署的主要或次要版本。

+   `DBInstanceClass`：用于运行数据库的 RDS 实例类型。为了确保您有资格获得免费使用，您可以将其硬编码为`db.t2.micro`，尽管在生产环境中，您通常会将此属性参数化为更大的实例大小。

+   `AllocatedStorage`和`StorageType`：定义以 GB 为单位的存储量和存储类型。在第一个示例中，存储类型设置为 10GB 的基于 SSD 的 gp2（通用用途 2）存储。

+   `MasterUsername`和`MasterUserPassword`：指定为 RDS 实例配置的主用户名和密码。`MasterUserPassword`属性引用了一个名为`DatabasePassword`的输入参数，其中包括一个名为`NoEcho`的属性，确保 CloudFormation 不会在任何日志中打印出此参数的值。

+   `DBName`：指定数据库的名称。

+   `VPCSecurityGroups`：要应用于 RDS 实例的网络通信入口和出口的安全组列表。

+   `DBSubnetGroupName`：引用`AWS::RDS::DBSubnetGroup`类型的资源，该资源定义 RDS 实例可以部署到的子网。请注意，即使您只配置了单可用区 RDS 实例，您仍然需要引用您创建的数据库子网组资源中的至少两个子网。在前面的例子中，您引用了一个名为`ApplicationDatabaseSubnetGroup`的资源，稍后将创建该资源。

+   `MultiAZ`：定义是否在高可用的多可用区配置中部署 RDS 实例。对于演示应用程序，可以将此设置配置为`false`，但在实际应用程序中，您通常会将此设置配置为`true`，至少对于生产环境是这样。

+   `AvailabilityZone`：定义 RDS 实例将部署到的可用区。此设置仅适用于单可用区实例（即`MultiAZ`设置为 false 的实例）。在前面的例子中，您使用`AWS::Region`伪参数来引用本地区域中可用区`a`。

# 配置支持的 RDS 资源

回顾前面的例子，很明显您需要配置至少两个额外的支持资源用于 RDS 实例：

+   `ApplicationDatabaseSecurityGroup`：定义应用于 RDS 实例的入站和出站安全规则的安全组资源。

+   `ApplicationDatabaseSubnetGroup`：RDS 实例可以部署到的子网列表。

除了这些资源，以下示例还演示了我们还需要添加一些资源：

```
...

Resources:
  ApplicationDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: MySQL
      EngineVersion: 5.7
      DBInstanceClass: db.t2.micro
      AllocatedStorage: 10
      StorageType: gp2
      MasterUsername: todobackend
      MasterUserPassword:
        Ref: DatabasePassword
      DBName: todobackend
      VPCSecurityGroups:
        - !Ref ApplicationDatabaseSecurityGroup
      DBSubnetGroupName: !Ref ApplicationDatabaseSubnetGroup
      MultiAZ: "false"
      AvailabilityZone: !Sub ${AWS::Region}a
      Tags:
        - Key: Name
          Value: !Sub ${AWS::StackName}-db
 ApplicationDatabaseSubnetGroup:
    Type: AWS::RDS::DBSubnetGroup
    Properties:
      DBSubnetGroupDescription: Application Database Subnet Group
      SubnetIds: !Ref ApplicationSubnets
      Tags:
        - Key: Name
          Value: !Sub ${AWS::StackName}-db-subnet-group
  ApplicationDatabaseSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: !Sub ${AWS::StackName} Application Database Security Group
      VpcId: !Ref VpcId
      SecurityGroupEgress:
        - IpProtocol: icmp
          FromPort: -1
          ToPort: -1
          CidrIp: 192.0.2.0/32
      Tags:
        - Key: Name
          Value: !Sub ${AWS::StackName}-db-sg
  ApplicationToApplicationDatabaseIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      IpProtocol: tcp
      FromPort: 3306
      ToPort: 3306
      GroupId: !Ref ApplicationDatabaseSecurityGroup
      SourceSecurityGroupId: !Ref ApplicationAutoscalingSecurityGroup
  ApplicationToApplicationDatabaseEgress:
    Type: AWS::EC2::SecurityGroupEgress
    Properties:
      IpProtocol: tcp
      FromPort: 3306
      ToPort: 3306
      GroupId: !Ref ApplicationAutoscalingSecurityGroup
      DestinationSecurityGroupId: !Ref ApplicationDatabaseSecurityGroup
...
...
```

创建支持的 RDS 资源

在前面的例子中，您首先创建了数据库子网组资源，其中 SubnetIds 属性引用了您在第七章中创建的相同的`ApplicationSubnets`列表参数，这意味着您的数据库实例将安装在与应用程序 ECS 集群和 EC2 自动扩展组实例相同的子网中。在生产应用程序中，您通常会在单独的专用子网上运行 RDS 实例，理想情况下，出于安全目的，该子网不会连接到互联网，但出于简化示例的目的，我们将利用与应用程序 ECS 集群相同的子网。

接下来，您创建了一个名为`ApplicationDatabaseSecurityGroup`的安全组资源，并注意到它只包含一个出站规则，有点奇怪的是允许对 IP 地址`192.0.2.0/32`进行 ICMP 访问。这个 IP 地址是"TEST-NET" IP 地址范围的一部分，是互联网上的无效 IP 地址，用于示例代码和文档。包含这个作为出站规则的原因是，AWS 默认情况下会自动应用一个允许任何规则的出站规则，除非您明确覆盖这些规则，因此通过添加一个允许访问无法路由的 IP 地址的规则，您实际上阻止了 RDS 实例发起的任何出站通信。

最后，请注意，您创建了两个与安全组相关的资源，`ApplicationToApplicationDatabaseIngress`和`ApplicationToApplicationDatabaseEgress`，它们分别具有`AWS::EC2::SecurityGroupIngress`和`AWS::EC2::SecurityGroupEgress`的资源类型。这些特殊资源避免了在 CloudFormation 中出现的一个问题，即创建了两个需要相互引用的资源之间的循环依赖。在我们的具体场景中，我们希望允许`ApplicationAutoscalingSecurityGroup`的成员访问`ApplicationDatabaseSecurityGroup`的成员，并应用适当的安全规则，从应用程序数据库中进行入站访问，并从应用程序实例中进行出站访问。如果您尝试按照以下图表所示的规则进行配置，CloudFormation 将抛出错误并检测到循环依赖。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/0139e646-f450-4086-99aa-09fc2e454a4a.png)CloudFormation 循环依赖

为了解决这个问题，以下图表演示了一种替代方法，使用了您在上一个示例中创建的资源。

`ApplicationToApplicationDatabaseIngress`资源将动态创建`ApplicationDatabaseSecurityGroup`中的入口规则（由`GroupId`属性指定），允许从`ApplicationAutoscalingSecurityGroup`（由`SourceSecurityGroupId`属性指定）访问 MySQL 端口（TCP/3306）。同样，`ApplicationToApplicationDatabaseEgress`资源将动态创建`ApplicationAutoscalingSecurityGroup`中的出口规则（由`GroupId`属性指定），允许访问属于`ApplicationDatabaseSecurityGroup`的实例的 MySQL 端口（TCP/3306）（由`DestinationSecurityGroupId`属性指定）。这最终实现了前面图表中所示配置的意图，但不会在 CloudFormation 中引起任何循环依赖错误。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4abce996-823e-4813-a977-7975e8894666.png)解决 CloudFormation 循环依赖

# 使用 CloudFormation 部署 RDS 资源

在上述示例的配置完成后，您现在可以实际更新 CloudFormation 堆栈，其中将添加 RDS 实例和其他支持资源。在执行此操作之前，您需要更新第七章中创建的`dev.cfg`文件，该文件为您的 CloudFormation 堆栈提供了环境特定的输入参数值。具体来说，您需要为`MasterPassword`参数指定一个值，如下例所示：

```
ApplicationDesiredCount=1
ApplicationImageId=ami-ec957491
ApplicationSubnets=subnet-a5d3ecee,subnet-324e246f
DatabasePassword=my-super-secret-password
VpcId=vpc-f8233a80
```

向 dev.cfg 文件添加数据库密码

此时，如果您对于以明文提供最终将提交到源代码中的密码感到担忧，那么恭喜您，您对于这种方法感到非常担忧是完全正确的。在接下来的章节中，我们将专门讨论如何安全地管理凭据，但目前我们不会解决这个问题，因此请记住，上述示例中演示的方法并不被认为是最佳实践，我们只会暂时保留这个方法来使您的应用数据库实例正常运行。

在上述示例的配置完成后，您现在可以使用在第七章中使用过的`aws cloudformation deploy`命令来部署更新后的堆栈。

```
> export AWS_PROFILE=docker-in-aws
> aws cloudformation deploy --template-file stack.yml \
 --stack-name todobackend --parameter-overrides $(cat dev.cfg) \
 --capabilities CAPABILITY_NAMED_IAM
Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga:
```

```
Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - todobackend
> aws cloudformation describe-stack-resource --stack-name todobackend \
    --logical-resource-id ApplicationDatabase
{
    "StackResourceDetail": {
        "StackName": "todobackend",
        "StackId": "arn:aws:cloudformation:us-east-1:385605022855:stack/todobackend/297933f0-37fe-11e8-82e0-503f23fb55fe",
        "LogicalResourceId": "ApplicationDatabase",
 "PhysicalResourceId": "ta10udhxgd7s4gf",
        "ResourceType": "AWS::RDS::DBInstance",
        "LastUpdatedTimestamp": "2018-04-04T12:12:13.265Z",
        "ResourceStatus": "CREATE_COMPLETE",
        "Metadata": "{}"
    }
}
> aws rds describe-db-instances --db-instance-identifier ta10udhxgd7s4gf
{
    "DBInstances": [
        {
            "DBInstanceIdentifier": "ta10udhxgd7s4gf",
            "DBInstanceClass": "db.t2.micro",
            "Engine": "mysql",
            "DBInstanceStatus": "available",
            "MasterUsername": "todobackend",
            "DBName": "todobackend",
            "Endpoint": {
                "Address": "ta10udhxgd7s4gf.cz8cu8hmqtu1.us-east-1.rds.amazonaws.com",
                "Port": 3306,
                "HostedZoneId": "Z2R2ITUGPM61AM"
            }
...
...
```

使用 RDS 资源更新 CloudFormation 堆栈

部署将需要一些时间（通常为 15-20 分钟）才能完成，一旦部署完成，请注意您可以使用`aws cloudformation describe-stack-resource`命令获取有关`ApplicationDatabase`资源的更多信息，包括`PhysicalResourceId`属性，该属性指定了 RDS 实例标识符。

# 配置应用负载均衡器

我们已经建立了一个 ECS 集群并创建了一个应用程序数据库来存储应用程序数据，接下来我们需要创建前端基础设施，以服务于外部世界对我们的 Docker 应用程序的连接。

在 AWS 中提供这种基础设施的一种流行方法是利用弹性负载均衡服务，该服务提供了多种不同的选项，用于负载均衡连接到您的应用程序：

+   **经典弹性负载均衡器**：原始的 AWS 负载均衡器，支持第 4 层（TCP）负载均衡。一般来说，您应该使用较新的应用负载均衡器或网络负载均衡器，它们共同提供了经典负载均衡器的所有现有功能以及更多功能。

+   **应用负载均衡器**：一种特别针对基于 Web 的应用程序和 API 的 HTTP 感知负载均衡器。

+   **网络负载均衡器**：高性能的第 4 层（TCP）负载均衡服务，通常用于非 HTTP 基于 TCP 的应用程序，或者需要非常高性能的应用程序。

对于我们的目的，我们将利用应用负载均衡器（ALB），这是一个现代的第 7 层负载均衡器，可以根据 HTTP 协议信息执行高级操作，例如基于主机头和基于路径的路由。例如，ALB 可以将针对特定 HTTP 主机头的请求路由到一组特定的目标，并且还可以将针对 some.domain/foo 路径的请求路由到一组目标，将针对 some.domain/bar 路径的请求路由到另一组目标。

AWS ALB 与弹性容器服务集成，支持许多关键的集成功能：

+   **滚动更新**：ECS 服务可以以滚动方式部署，ECS 利用负载均衡器连接排空来优雅地将旧版本的应用程序停止服务，终止并替换每个应用程序容器为新版本，然后将新容器添加到负载均衡器，确保更新在没有最终用户中断或影响的情况下进行。

+   **动态端口映射**：此功能允许您将容器端口映射到 ECS 容器实例上的动态端口，ECS 负责确保动态端口映射正确地注册到应用负载均衡器。动态端口映射的主要好处是它允许同一应用程序容器的多个实例在单个 ECS 容器实例上运行，从而在维度和扩展 ECS 集群方面提供了更大的灵活性。

+   **健康检查**：ECS 使用应用负载均衡器的健康检查来确定您的 Docker 应用程序的健康状况，自动终止和替换任何可能变得不健康并且无法通过负载均衡器健康检查的容器。

# 应用负载均衡器架构

如果您熟悉旧版经典弹性负载均衡器，您会发现新版应用负载均衡器的架构更加复杂，因为 ALB 支持高级的第 7 层/HTTP 功能。

以下图显示了组成应用负载均衡器的各种组件：

应用负载均衡器组件

以下描述了上图中所示的每个组件：

+   **应用负载均衡器**：应用负载均衡器是定义负载均衡器的物理资源，例如负载均衡器应该运行在哪些子网以及允许或拒绝网络流量到负载均衡器或从负载均衡器流出的安全组。

+   **监听器**：监听器定义了终端用户和设备连接的网络端口。您可以将监听器视为负载均衡器的前端组件，为传入连接提供服务，最终将被路由到托管应用程序的目标组。每个应用负载均衡器可以包括多个监听器——一个常见的例子是监听器配置，可以为端口`80`和端口`443`的网络流量提供服务。

+   **监听规则**：监听规则可选择性地根据接收到的主机标头和/或请求路径的值将由监听器接收的 HTTP 流量路由到不同的目标组。例如，如前图所示，您可以将发送到`/foo/*`请求路径的所有流量路由到一个目标组，而将发送到`/bar/*`的所有流量路由到另一个目标组。请注意，每个监听器必须定义一个默认目标组，所有未路由到监听规则的流量将被路由到该目标组。

+   **目标组**：目标组定义了应该路由到的一个或多个目标的传入连接。您可以将目标组视为负载均衡器的后端组件，负责将接收到的连接负载均衡到目标组中的成员。在将应用程序负载均衡器与 ECS 集成时，目标组链接到 ECS 服务，每个 ECS 服务实例（即容器）被视为单个目标。

# 配置应用程序负载均衡器

现在您已经了解了应用程序负载均衡器的基本架构，让我们在您的 CloudFormation 模板中定义各种应用程序负载均衡器组件，并继续将新资源部署到您的 CloudFormation 堆栈中。

# 创建应用程序负载均衡器

以下示例演示了如何添加一个名为`ApplicationLoadBalancer`的资源，正如其名称所示，它配置了基本的应用程序负载均衡器资源：

```
...
...
Resources:
 ApplicationLoadBalancer:
 Type: AWS::ElasticLoadBalancingV2::LoadBalancer
 Properties:
 Scheme: internet-facing
 Subnets: !Ref ApplicationSubnets
 SecurityGroups:
 - !Ref ApplicationLoadBalancerSecurityGroup
 LoadBalancerAttributes:
 - Key: idle_timeout.timeout_seconds
 Value : 30
 Tags:
 - Key: Name
 Value: !Sub ${AWS::StackName}-alb
  ApplicationDatabase:
    Type: AWS::RDS::DBInstance
...
...
```

创建应用程序负载均衡器

在上述示例中，为应用程序负载均衡器资源配置了以下属性：

+   `方案`：定义负载均衡器是否具有公共 IP 地址（由值`internet-facing`指定）或仅具有私有 IP 地址（由值`internal`指定）

+   `子网`：定义了应用程序负载均衡器端点将部署到的子网。在上述示例中，您引用了`ApplicationSubnets`输入参数，该参数之前已用于 EC2 自动扩展组和 RDS 数据库实例资源。

+   `安全组`：指定要应用于负载均衡器的安全组列表，限制入站和出站网络流量。您引用了一个名为`ApplicationLoadBalancerSecurityGroup`的安全组，稍后将创建该安全组。

+   `LoadBalancerAttributes`：以键/值格式配置应用程序负载均衡器的各种属性。您可以在[`docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes`](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes)找到支持的属性列表，在前面的示例中，您配置了一个属性，将空闲连接超时从默认值`60`秒减少到`30`秒。

CloudFormation 的一个特性是能够定义自己的*输出*，这些输出可用于提供有关堆栈中资源的信息。您可以为堆栈配置一个有用的输出，即应用程序负载均衡器端点的公共 DNS 名称的值，因为这是负载均衡器提供的任何应用程序发布的地方：

```
...
...
Resources:
  ...
  ...
Outputs:
 PublicURL:
 Description: Public DNS name of Application Load Balancer
 Value: !Sub ${ApplicationLoadBalancer.DNSName}

```

配置 CloudFormation 输出

在前面的例子中，请注意`ApplicationLoadBalancer`资源输出一个名为`DNSName`的属性，该属性返回`ApplicationLoadBalancer`资源的公共 DNS 名称。

# 配置应用程序负载均衡器安全组

在前面的例子中，您引用了一个名为`ApplicationLoadBalancerSecurityGroup`的资源，该资源定义了对应用程序负载均衡器的入站和出站网络访问。

除了这个资源，您还需要以类似的方式创建`AWS::EC2::SecurityGroupIngress`和`AWS::EC2::SecurityGroupEgress`资源，这些资源确保应用程序负载均衡器可以与您的 ECS 服务应用程序实例通信：

```
...
...
Resources:
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Scheme: internet-facing
      Subnets: !Ref ApplicationSubnets
      SecurityGroups:
        - !Ref ApplicationLoadBalancerSecurityGroup
      LoadBalancerAttributes:
        - Key: idle_timeout.timeout_seconds
          Value : 30
      Tags:
        - Key: Name
          Value: !Sub ${AWS::StackName}-alb
  ApplicationLoadBalancerSecurityGroup:
 Type: AWS::EC2::SecurityGroup
 Properties:
 GroupDescription: Application Load Balancer Security Group
 VpcId: !Ref VpcId
 SecurityGroupIngress:
 - IpProtocol: tcp
 FromPort: 80
 ToPort: 80
 CidrIp: 0.0.0.0/0
 Tags:
 - Key: Name
 Value: 
 Fn::Sub: ${AWS::StackName}-alb-sg  ApplicationLoadBalancerToApplicationIngress:
 Type: AWS::EC2::SecurityGroupIngress
 Properties:
 IpProtocol: tcp
 FromPort: 32768
 ToPort: 60999
 GroupId: !Ref ApplicationAutoscalingSecurityGroup
 SourceSecurityGroupId: !Ref ApplicationLoadBalancerSecurityGroup
 ApplicationLoadBalancerToApplicationEgress:
 Type: AWS::EC2::SecurityGroupEgress
 Properties:
 IpProtocol: tcp
 FromPort: 32768
 ToPort: 60999
 GroupId: !Ref ApplicationLoadBalancerSecurityGroup
 DestinationSecurityGroupId: !Ref ApplicationAutoscalingSecurityGroup
  ApplicationDatabase:
    Type: AWS::RDS::DBInstance
...
...
```

配置应用程序负载均衡器安全组资源

在前面的例子中，您首先创建了`ApplicationLoadBalancerSecurityGroup`资源，允许从互联网访问端口 80。`ApplicationLoadBalancerToApplicationIngress`和`ApplicationLoadBalancerToApplicationEgress`资源向`ApplicationLoadBalancerSecurityGroup`和`ApplicationAutoscalingSecurityGroup`资源添加安全规则，而不会创建循环依赖（请参阅前面的图表和相关描述），请注意这些规则引用了应用程序自动缩放组的短暂端口范围`32768`到`60999`，因为我们将为您的 ECS 服务配置动态端口映射。

# 创建一个监听器

现在，您已经建立了基本的应用程序负载均衡器和相关的安全组资源，可以为应用程序负载均衡器配置一个监听器。对于本书的目的，您只需要配置一个支持 HTTP 连接的单个监听器，但在任何真实的生产用例中，您通常会为任何面向互联网的服务配置 HTTPS 监听器以及相关证书。

以下示例演示了配置一个支持通过端口`80`（HTTP）访问应用程序负载均衡器的单个监听器：

```
...
...
Resources:
  ApplicationLoadBalancerHttpListener:
 Type: AWS::ElasticLoadBalancingV2::Listener
 Properties:
 LoadBalancerArn: !Ref ApplicationLoadBalancer
 Protocol: HTTP
 Port: 80
 DefaultActions:
 - TargetGroupArn: !Ref ApplicationServiceTargetGroup
 Type: forward
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Scheme: internet-facing
      Subnets: !Ref ApplicationSubnets
      SecurityGroups:
        - !Ref ApplicationLoadBalancerSecurityGroup
      LoadBalancerAttributes:
        - Key: idle_timeout.timeout_seconds
          Value : 30
      Tags:
        - Key: Name
          Value: !Sub ${AWS::StackName}-alb
...
...
```

创建应用程序负载均衡器监听器

在上面的示例中，通过`LoadBalancerArn`属性将监听器绑定到`ApplicationLoadBalancer`资源，`Protocol`和`Port`属性配置监听器以期望在端口`80`上接收传入的 HTTP 连接。请注意，您必须定义`DefaultActions`属性，该属性定义了传入连接将被转发到的默认目标组。

# 创建目标组

与配置应用程序负载均衡器相关的最终配置任务是配置目标组，该目标组将用于将监听器资源接收的传入请求转发到应用程序实例。

以下示例演示了配置目标组资源：

```
...
...
Resources:
  ApplicationServiceTargetGroup:
 Type: AWS::ElasticLoadBalancingV2::TargetGroup
 Properties:
 Protocol: HTTP
 Port: 8000
 VpcId: !Ref VpcId
 TargetGroupAttributes:
 - Key: deregistration_delay.timeout_seconds
 Value: 30
  ApplicationLoadBalancerHttpListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref ApplicationLoadBalancer
      Protocol: HTTP
      Port: 80
      DefaultActions:
        - TargetGroupArn: !Ref ApplicationServiceTargetGroup
          Type: forward
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
...
...
```

创建目标组

在上面的示例中，为目标组定义了以下配置：

+   `Protocol`：定义将转发到目标组的连接的协议。

+   `Port`：指定应用程序将运行的容器端口。默认情况下，todobackend 示例应用程序在端口`8000`上运行，因此您可以为端口配置此值。请注意，当配置动态端口映射时，ECS 将动态重新配置此端口。

+   `VpcId`：配置目标所在的 VPC ID。

+   `TargetGroupAttributes`：定义了目标组的配置属性（[`docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-group-attributes`](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-group-attributes)），在上面的示例中，`deregistration_delay.timeout_seconds`属性配置了在滚动部署应用程序期间排空连接时等待取消注册目标的时间。

# 使用 CloudFormation 部署应用负载均衡器

现在，您的 CloudFormation 模板中已经定义了所有应用负载均衡器组件，您可以使用`aws cloudformation deploy`命令将这些组件部署到 AWS。

一旦您的堆栈部署完成，如果您打开 AWS 控制台并导航到 EC2 仪表板，在**负载均衡**部分，您应该能够看到您的新应用负载均衡器资源。

以下截图演示了查看作为部署的一部分创建的应用负载均衡器资源：

查看应用负载均衡器

在前面的截图中，您可以看到应用负载均衡器资源有一个 DNS 名称，这是您的最终用户和设备在访问负载均衡器后面的应用时需要连接的端点名称。一旦您完全部署了堆栈中的所有资源，您将在稍后使用这个名称，但是现在因为您的目标组是空的，这个 URL 将返回一个 503 错误，如下例所示。请注意，您可以通过单击前面截图中的**监听器**选项卡来查看您的监听器资源，您可以通过单击左侧菜单上的**目标组**链接来查看您的关联目标组资源。

您会注意到应用负载均衡器的 DNS 名称并不是您的最终用户能够识别或记住的友好名称。在实际应用中，您通常会创建一个 CNAME 或 ALIAS DNS 记录，配置一个友好的规范名称，比如 example.com，指向您的负载均衡器 DNS 名称。有关如何执行此操作的更多详细信息，请参阅[`docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-to-elb-load-balancer.html`](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-to-elb-load-balancer.html)，并注意您可以并且应该使用 CloudFormation 创建 CNAME 和 ALIAS 记录([`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-route53.html#scenario-recordsetgroup-zoneapex`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-route53.html#scenario-recordsetgroup-zoneapex))。

```
> aws cloudformation describe-stacks --stack-name todobackend --query Stacks[].Outputs[]
[
    {
        "OutputKey": "PublicURL",
        "OutputValue": "todob-Appli-5SV5J3NC6AAI-2078461159.us-east-1.elb.amazonaws.com",
        "Description": "Public DNS name of Application Load Balancer"
    }
]
> curl todob-Appli-5SV5J3NC6AAI-2078461159.us-east-1.elb.amazonaws.com
<html>
<head><title>503 Service Temporarily Unavailable</title></head>
<body bgcolor="white">
<center><h1>503 Service Temporarily Unavailable</h1></center>
</body>
</html>
```

测试应用负载均衡器端点

请注意，在上面的示例中，您可以使用 AWS CLI 来查询 CloudFormation 堆栈的输出，并获取应用程序负载均衡器的公共 DNS 名称。您还可以在 CloudFormation 仪表板中选择堆栈后，单击“输出”选项卡来查看堆栈的输出。

# 创建 ECS 任务定义

您现在已经达到了定义使用 CloudFormation 的 ECS 集群并创建了许多支持资源的阶段，包括用于应用程序数据库的 RDS 实例和用于服务应用程序连接的应用程序负载均衡器。

在这个阶段，您已经准备好创建将代表您的应用程序的 ECS 资源，包括 ECS 任务定义和 ECS 服务。

我们将从在 CloudFormation 模板中定义 ECS 任务定义开始，如下例所示：

```
Parameters:
  ...
  ...
  ApplicationImageId:
    Type: String
    Description: ECS Amazon Machine Image (AMI) ID
 ApplicationImageTag:
 Type: String
 Description: Application Docker Image Tag
 Default: latest  ApplicationSubnets:
    Type: List<AWS::EC2::Subnet::Id>
    Description: Target subnets for EC2 instances
 ...
  ... 
Resources:
  ApplicationTaskDefinition:
 Type: AWS::ECS::TaskDefinition
 Properties:
 Family: todobackend      Volumes:
 - Name: public          Host:
 SourcePath: /data/public
 ContainerDefinitions:        - Name: todobackend
 Image: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/docker-in-aws/todobackend:${ApplicationImageTag}
 MemoryReservation: 395
 Cpu: 245
 MountPoints:
 - SourceVolume: public
 ContainerPath: /public
 Environment:
            - Name: DJANGO_SETTINGS_MODULE
 Value: todobackend.settings_release
 - Name: MYSQL_HOST
 Value: !Sub ${ApplicationDatabase.Endpoint.Address}
 - Name: MYSQL_USER
 Value: todobackend
 - Name: MYSQL_PASSWORD
 Value: !Ref DatabasePassword
 - Name: MYSQL_DATABASE
 Value: todobackend            - Name: SECRET_KEY
 Value: some-random-secret-should-be-here
 Command: 
 - uwsgi
 - --http=0.0.0.0:8000
 - --module=todobackend.wsgi
 - --master
 - --die-on-term
 - --processes=4
 - --threads=2
 - --check-static=/public
 PortMappings:
 - ContainerPort: 8000
              HostPort: 0
 LogConfiguration:
 LogDriver: awslogs
 Options:
 awslogs-group: !Sub /${AWS::StackName}/ecs/todobackend
 awslogs-region: !Ref AWS::Region
 awslogs-stream-prefix: docker
 - Name: collectstatic
          Essential: false
 Image: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/docker-in-aws/todobackend:${ApplicationImageTag}
 MemoryReservation: 5
 Cpu: 5          MountPoints:
 - SourceVolume: public
              ContainerPath: /public
 Environment:
 - Name: DJANGO_SETTINGS_MODULE
              Value: todobackend.settings_release
 Command:
 - python3
            - manage.py
            - collectstatic
            - --no-input
 LogConfiguration:
 LogDriver: awslogs
 Options:
 awslogs-group: !Sub /${AWS::StackName}/ecs/todobackend
 awslogs-region: !Ref AWS::Region
 awslogs-stream-prefix: docker  ApplicationLogGroup:
 Type: AWS::Logs::LogGroup
 Properties:
 LogGroupName: !Sub /${AWS::StackName}/ecs/todobackend
 RetentionInDays: 7
  ApplicationServiceTargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
...
...
```

使用 CloudFormation 定义 ECS 任务定义

正如您在上面的示例中所看到的，配置任务定义需要合理的配置量，并需要对任务定义所代表的容器应用程序的运行时配置有详细的了解。

在第一章中，当您创建了示例应用并在本地运行时，您必须使用 Docker Compose 执行类似的操作。以下示例显示了 todobackend 存储库中 Docker Compose 文件中的相关片段：

```
version: '2.3'

volumes:
  public:
    driver: local

services:
  ...
  ...
  app:
    image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:${APP_VERSION}
    extends:
      service: release
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - public:/public
    healthcheck:
      test: curl -fs localhost:8000
    ports:
      - 8000
    command:
      - uwsgi
      - --http=0.0.0.0:8000
      - --module=todobackend.wsgi
      - --master
      - --die-on-term
      - --processes=4
      - --threads=2
      - --check-static=/public
  acceptance:
    extends:
      service: release
    depends_on:
      app:
        condition: service_healthy
    environment:
      APP_URL: http://app:8000
    command:
      - bats 
      - acceptance.bats
  migrate:
    extends:
      service: release
    depends_on:
      db:
        condition: service_healthy
    command:
      - python3
      - manage.py
      - migrate
      - --no-input
  ...
  ...
```

Todobackend 应用程序 Docker Compose 配置

如果您比较前面两个示例的配置，您会发现您可以使用本地 Docker Compose 配置来确定 ECS 任务定义所需的配置。

现在让我们更详细地检查各种 ECS 任务定义配置属性。

# 配置 ECS 任务定义家族

您在任务定义中定义的第一个属性是**Family**属性，它建立了 ECS 任务定义家族名称，并影响 CloudFormation 在您对任务定义进行更改时创建新实例的方式。

回想一下第四章中，ECS 任务定义支持修订的概念，您可以将其视为 ECS 任务定义的特定版本或配置，每当您需要修改任务定义（例如修改镜像标签）时，您可以创建 ECS 任务定义的新修订版本。

因此，如果您的 ECS 任务定义族名称为**todobackend**，则任务定义的第一个修订版将为**todobackend:1**，对任务定义的任何后续更改都将导致创建一个新的修订版，例如**todobackend:2**，**todobackend:3**等。配置 ECS 任务定义资源中的**Family**属性可确保 CloudFormation 在修改 ECS 任务定义资源时采用创建新修订版的行为。

请注意，如果您未按照之前的示例配置**Family**属性，CloudFormation 将为族生成一个随机名称，修订版为 1，对任务定义的任何后续更改都将导致创建一个*新*的族，其名称随机，修订版仍为 1。

# 配置 ECS 任务定义卷

回顾之前示例中的`ApplicationTaskDefinition`资源，`Volumes`属性定义了每当 ECS 任务定义的实例部署到 ECS 容器实例时将创建的本地 Docker 卷。参考之前示例中的本地 Docker Compose 配置，您可以看到配置了一个名为**public**的卷，然后在**app**服务定义中引用为挂载点。

该卷用于存储静态网页文件，这些文件是通过在本地 Makefile 工作流中运行`python3 manage.py collectstatic --no-input`命令生成的，并且必须对主应用程序容器可用，因此需要一个卷来确保通过运行此命令生成的文件对应用程序容器可用：

```
...
...
release:
  docker-compose up --abort-on-container-exit migrate
 docker-compose run app python3 manage.py collectstatic --no-input
  docker-compose up --abort-on-container-exit acceptance
  @ echo App running at http://$$(docker-compose port app 8000 | sed s/0.0.0.0/localhost/g)
...
...
```

Todobackend Makefile

请注意，在我们的 ECS 任务定义中，我们还需要指定一个主机源路径`/data/public`，这是我们在上一章中作为 ECS 集群自动扩展组 CloudFormation init 配置的一部分创建的。该文件夹在底层 ECS 容器实例上具有正确的权限，这确保我们的应用程序能够读取和写入公共卷。

# 配置 ECS 任务定义容器

之前配置的 ECS 任务定义包括`ContainerDefinitions`属性，该属性定义了与任务定义关联的一个或多个容器的列表。您可以看到有两个容器被定义：

+   `todobackend`容器：这是主应用程序容器定义。

+   `collectstatic`容器：这个容器是一个短暂的容器，运行`python3 manage.py collectstatic`命令来生成本地静态网页文件。与这个容器相关的一个重要配置参数是`Essential`属性，它定义了 ECS 是否应该尝试重新启动容器，如果它失败或退出（事实上，ECS 将尝试重新启动任务定义中的所有容器，导致主应用容器不必要地停止和重新启动）。鉴于`collectstatic`容器只打算作为短暂的任务运行，您必须将此属性设置为 false，以确保 ECS 不会尝试重新启动您的 ECS 任务定义容器。

有许多方法可以满足运行收集静态过程以生成静态网页文件的要求。例如，您可以定义一个启动脚本，首先运行收集静态，然后启动应用程序容器，或者您可能希望将静态文件发布到 S3 存储桶，这意味着您将以完全不同的方式运行收集静态过程。

除了 Essential 属性之外，`todobackend`和`collectstatic`容器定义的配置属性非常相似，因此我们将在这里仅讨论主`todobackend`容器定义的属性，并在适当的地方讨论与`collectstatic`容器定义的任何差异。

+   `Image`：此属性定义了容器基于的 Docker 镜像的 URI。请注意，我们发布了您在第五章创建的 ECR 存储库的 URI，用于 todobackend 应用程序，并引用了一个名为`ApplicationImageTag`的堆栈参数，这允许您在部署堆栈时提供适当版本的 Docker 镜像。

+   `Cpu` 和 `MemoryReservation`：这些属性为您的容器分配 CPU 和内存资源。我们将在接下来的章节中更详细地讨论这些资源，但现在要明白，这些值保留了配置的 CPU 分配和内存，但允许您的容器在可用时使用更多的 CPU 和内存（即“burst”）。请注意，您为 `collectstatic` 容器分配了最少量的 CPU 和内存，因为它只需要运行很短的时间，而且很可能 ECS 容器实例将有多余的 CPU 和内存容量可用来满足容器的实际资源需求。这避免了为只在一小部分时间内活动的容器保留大量的 CPU 和内存。

+   `MountPoints`：定义将挂载到容器的 Docker 卷。每个容器都有一个单独的挂载点，将 **public** 卷挂载到 `/public` 容器路径，用于托管静态网页文件。

+   `Environment`：定义将可用于容器的环境变量。参考前面示例中的本地 Docker Compose 配置，您可以看到 release 服务，这是应用服务继承的基本服务定义，指示容器需要将 `DJANGO_SETTINGS_MODULE` 变量设置为 `todobackend.settings_release`，并需要定义一些与数据库相关的环境变量，以定义与应用程序数据库的连接。另一个需要的环境变量是 `SECRET_KEY` 变量，它用于 Django 框架中的各种加密功能，用于驱动 todobackend 应用程序，应该配置为一个秘密的随机值。正如您所看到的，现在我们设置了一个相当非随机的明文值，下一章中，您将学习如何将此值作为加密的秘密注入。

+   `Command`：定义启动容器时应执行的命令。您可以看到 `todobackend` 容器定义使用了与本地 Docker Compose 工作流使用的相同的 `uwsgi` 命令来启动 `uwsgi` 应用服务器，而 `collectstatic` 容器使用 `python3 manage.py collectstatic` 命令来生成要从主应用程序提供的静态网页文件。

+   `PortMappings`：指定应从容器公开的端口映射。todobackend 容器定义有一个单一的端口映射，指定了容器端口的默认应用程序端口`8000`，并指定了主机端口值为`0`，这意味着将使用动态端口映射（请注意，当使用动态端口映射时，您也可以省略 HostPort 参数）。

+   `LogConfiguration`：配置容器的日志记录配置。在前面的示例中，您使用 awslogs 驱动程序配置 CloudWatch 日志作为日志驱动程序，然后配置特定于此驱动程序的选项。awslogs-group 选项指定日志将输出到的日志组，这引用了在`ApplicationLogGroup`资源下方定义的日志组的名称。awslogs-stream-prefix 非常重要，因为它修改了容器 ID 的默认日志流命名约定为`<prefix-name>/<container-name>/<ecs-task-id>`格式，这里的关键信息是 ECS 任务 ID，这是您在使用 ECS 时处理的主要任务标识，而不是容器 ID。

在第七章中，您授予了 ECS 容器实例发布到任何以您的 CloudFormation 堆栈名称为前缀的日志组的能力。只要您的 ECS 任务定义和相关的日志组遵循这个命名约定，Docker 引擎就能够将您的 ECS 任务和容器的日志发布到 CloudWatch 日志中。

# 使用 CloudFormation 部署 ECS 任务定义

现在您已经定义了 ECS 任务定义，您可以使用现在熟悉的`aws cloudformation deploy`命令部署它。一旦您的堆栈已经更新，一个名为 todobackend 的新任务定义应该被创建，您可以使用 AWS CLI 查看，如下例所示：

```
> aws ecs describe-task-definition --task-definition todobackend
{
    "taskDefinition": {
        "taskDefinitionArn": "arn:aws:ecs:us-east-1:385605022855:task-definition/todobackend:1",
        "family": "todobackend",
        "revision": 1,
        "volumes": [
            {
                "name": "public",
                "host": {
                    "sourcePath": "/data/public"
                }
            }
        ],
        "containerDefinitions": [
            {
                "name": "todobackend",
                "image": "385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest",
                "cpu": 245,
                "memoryReservation": 395,
...
...
```

验证 todobackend 任务定义

# 部署 ECS 服务

有了您的 ECS 集群、ECS 任务定义和各种支持资源，现在您可以定义一个 ECS 服务，将您在 ECS 任务定义中定义的容器应用程序部署到您的 ECS 集群中。

以下示例演示了向您的 CloudFormation 模板添加一个`AWS::ECS::Service`资源的 ECS 服务资源：

```
...
...
Resources:
  ApplicationService:
 Type: AWS::ECS::Service
 DependsOn:
      - ApplicationAutoscaling
      - ApplicationLogGroup
      - ApplicationLoadBalancerHttpListener
    Properties:
      TaskDefinition: !Ref ApplicationTaskDefinition
      Cluster: !Ref ApplicationCluster
      DesiredCount: !Ref ApplicationDesiredCount
      LoadBalancers:
        - ContainerName: todobackend
          ContainerPort: 8000
          TargetGroupArn: !Ref ApplicationServiceTargetGroup
      Role: !Sub arn:aws:iam::${AWS::AccountId}:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS 
```

```
 DeploymentConfiguration:
 MaximumPercent: 200
 MinimumHealthyPercent: 100
  ApplicationTaskDefinition:
    Type: AWS::ECS::TaskDefinition
...
...
```

创建 ECS 服务

在前面的例子中，配置的一个有趣方面是`DependsOn`参数，它定义了堆栈中必须在创建或更新 ECS 服务资源之前创建或更新的其他资源。虽然 CloudFormation 在资源直接引用另一个资源时会自动创建依赖关系，但是一个资源可能对其他资源有依赖，而这些资源与该资源没有直接关系。ECS 服务资源就是一个很好的例子——服务在没有功能的 ECS 集群和相关的 ECS 容器实例（这由`ApplicationAutoscaling`资源表示）的情况下无法运行，并且在没有`ApplicationLogGroup`资源的情况下无法写入日志。一个更微妙的依赖关系是`ApplicationLoadBalancerHttpListener`资源，在与 ECS 服务关联的目标组注册目标之前必须是功能性的。

这里描述了为 ECS 服务配置的各种属性：

+   `TaskDefinition`、`DesiredCount`和`Cluster`：定义了 ECS 任务定义、ECS 任务数量和服务将部署到的目标 ECS 集群。

+   `LoadBalancers`：配置了 ECS 服务应该集成的负载均衡器资源。您必须指定容器名称、容器端口和 ECS 服务将注册的目标组 ARN。请注意，您引用了在本章前面创建的`ApplicationServiceTargetGroup`资源。

+   `Role`：如果要将 ECS 服务与负载均衡器集成，则只有在这种情况下才需要此属性，并且指定了授予 ECS 服务管理配置的负载均衡器权限的 IAM 角色。在前面的例子中，您引用了一个特殊的 IAM 角色的 ARN，这个角色被称为服务角色（[`docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html)），它在创建 ECS 资源时由 AWS 自动创建。`AWSServiceRoleForECS`服务角色授予了通常需要的 ECS 权限，包括管理和集成应用程序负载均衡器。

+   `DeploymentConfiguration`：配置与 ECS 任务定义的新版本滚动部署相关的设置。在部署过程中，ECS 将停止现有容器，并根据 ECS 任务定义的新版本部署新容器，`MinimumHealthyPercent`设置定义了在部署过程中必须处于服务状态的容器的最低允许百分比，与`DesiredCount`属性相关。同样，`MaximumPercent`设置定义了在部署过程中可以部署的容器的最大允许百分比，与`DesiredCount`属性相关。

# 使用 CloudFormation 部署 ECS 服务

在设置好 ECS 服务配置后，现在是时候使用`aws cloudformation deploy`命令将更改部署到您的堆栈了。部署完成后，您的 ECS 服务应该注册到您在本章前面创建的目标组中，如果您浏览到您的应用程序负载均衡器的 URL，您应该看到示例应用程序的根 URL 正在正确加载：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/68a5cac1-2c9c-4711-bb88-70eb0ee1e14e.png)测试 todobackend 应用程序

然而，如果您点击前面截图中显示的**todos**链接，您将收到一个错误，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b1ba0115-82ab-40ff-9473-2f5887ed15b7.png)todobackend 应用程序错误

在前面的截图中的问题是，应用程序数据库中预期的数据库表尚未创建，因为我们尚未对应用程序数据库运行数据库迁移。我们将很快学习如何解决这个问题，但在我们这样做之前，我们还有一个与部署 ECS 服务相关的主题要讨论：滚动部署。

# ECS 滚动部署

ECS 的一个关键特性是滚动部署，ECS 将自动以滚动方式部署应用程序的新版本，与您配置的负载均衡器一起协调各种操作，以确保您的应用程序成功部署，没有停机时间，也不会影响最终用户。ECS 如何管理滚动部署的过程实际上是非常详细的，以下图表试图以一个图表高层次地描述这个过程：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/9486bf16-31d9-4726-a3fb-d06d0fd92aeb.png)ECS 滚动部署

在前面的图表中，滚动部署期间发生了以下事件：

1.  对与 ECS 服务关联的`ApplicationTaskDefinition` ECS 任务定义进行配置更改，通常是应用程序新版本的镜像标签的更改，但也可能是对任务定义的任何更改。这将导致任务定义的新修订版被创建（在这个例子中是修订版 2）。

1.  ECS 服务配置为使用新的任务定义修订版，当使用 CloudFormation 来管理 ECS 资源时，这是自动发生的。ECS 服务的部署配置决定了 ECS 如何管理滚动部署-在前面的图表中，ECS 必须确保在部署过程中维持配置的期望任务数量的最低 100%，并且可以在部署过程中暂时增加任务数量达到最高 200%。假设期望的任务数量为 1，这意味着 ECS 可以部署基于新任务定义修订版的新 ECS 任务并满足部署配置。请注意，您的 ECS 集群必须有足够的资源来容纳这些部署，并且您负责管理 ECS 集群的容量（即 ECS 不会暂时增加 ECS 集群的容量来容纳部署）。您将在后面的章节中学习如何动态管理 ECS 集群的容量。

1.  一旦新的 ECS 任务成功启动，ECS 会将新任务注册到配置的负载均衡器（在应用负载均衡器的情况下，任务将被注册到目标组资源）。负载均衡器将执行健康检查来确定新任务的健康状况，一旦确认健康，新的 ECS 任务将被注册到负载均衡器并能够接受传入连接。

1.  ECS 现在指示负载均衡器排水现有的 ECS 任务。负载均衡器将使现有的 ECS 任务停止服务（即不会将任何新连接转发到任务），但会等待一段可配置的时间来使现有连接“排水”或关闭。在此期间，任何对负载均衡器的新连接将被转发到在第 3 步中向负载均衡器注册的新 ECS 任务。

1.  一旦排水过程完成，负载均衡器将完全从目标组中删除旧的 ECS 任务，ECS 现在可以终止现有的 ECS 任务。一旦这个过程完成，新应用任务定义的部署就完成了。

从这个描述中可以看出，部署过程非常复杂。好消息是，所有这些都可以通过 ECS 开箱即用——您需要理解的是，对任务定义的任何更改都将触发新的部署，并且您的部署配置，由 DeploymentConfiguration 属性确定，可以在滚动部署中对其进行一些控制。

# 执行滚动部署

现在您了解了滚动部署的工作原理，让我们通过对 ECS 任务定义进行更改并通过 CloudFormation 部署更改的过程来看看它的实际操作，这将触发 ECS 服务的滚动部署。

目前，您的 CloudFormation 配置未指定 ApplicationImageTag 参数，这意味着您的 ECS 任务定义正在使用 latest 的默认值。回到第五章，当您将 Docker 镜像发布到 ECR 时，实际上推送了两个标签——latest 标签和 todobackend 存储库的提交哈希。这为我们提供了一个很好的机会来进一步改进我们的 CloudFormation 模板——通过引用提交哈希，而不是 latest 标签，我们将始终能够在您有新版本的应用程序要部署时触发对 ECS 任务定义的配置更改。

以下示例演示了在 todobackend-aws 存储库中的 dev.cfg 文件中添加 ApplicationImageTag 参数，引用当前发布的 ECR 镜像的提交哈希：

```
ApplicationDesiredCount=1
ApplicationImageId=ami-ec957491
ApplicationImageTag=97e4abf
ApplicationSubnets=subnet-a5d3ecee,subnet-324e246f
VpcId=vpc-f8233a80
```

将 ApplicationImageTag 添加到 dev.cfg 文件

如果您现在使用 aws cloudformation deploy 命令部署更改，尽管您现在引用的镜像与当前 latest 标记的镜像相同，CloudFormation 将检测到这是一个配置更改，创建 ECS 任务定义的新修订版本，并更新 ApplicationService ECS 服务资源，触发滚动部署。

在部署运行时，如果您浏览 ECS 仪表板中的 ECS 服务并选择部署选项卡，如下截图所示，您将看到两个部署——ACTIVE 部署指的是现有的 ECS 任务，而 PRIMARY 部署指的是正在部署的新的 ECS 任务。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/44aab8c6-3a36-47ec-b224-74861afc4181.png)ECS 服务滚动部署

最终，一旦滚动部署过程完成，ACTIVE 部署将消失，如果您点击“事件”选项卡，您将看到部署过程中发生的各种事件，这些事件对应了先前的描述：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/adc2feb0-c12b-4822-b81d-0acf52cefc78.png)ECS 服务滚动部署事件

# 创建 CloudFormation 自定义资源

尽管我们的应用已经部署并运行，但很明显我们有一个问题，即我们尚未运行数据库迁移，这是一个必需的部署任务。我们已经处理了运行另一个部署任务，即收集静态文件，但是数据库迁移应该只作为*单个*部署任务运行。例如，如果您正在部署服务的多个实例，您不希望为每个部署的实例运行迁移，您只想在每个部署中运行一次迁移，而不管服务中有多少实例。

一个明显的解决方案是在每次部署后手动运行迁移，但是理想情况下，您希望完全自动化您的部署，并确保您有一种机制可以自动运行迁移。CloudFormation 不提供允许您运行一次性 ECS 任务的资源，但是 CloudFormation 的一个非常强大的功能是能够创建自己的自定义资源，这使您能够执行自定义的配置任务。创建自定义资源的好处是您可以将自定义的配置任务纳入部署各种 AWS 服务和资源的工作流程中，使用 CloudFormation 框架来为您管理这一切。

现在让我们学习如何创建一个简单的 ECS 任务运行器自定义资源，该资源将作为创建和更新应用程序环境的一部分来运行迁移任务。

# 理解 CloudFormation 自定义资源

在开始配置 CloudFormation 自定义资源之前，值得讨论它们实际上是如何工作的，并描述组成自定义资源的关键组件。

以下图表说明了 CloudFormation 自定义资源的工作原理：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a8738f96-3ab5-46a3-95dc-d5d9216a7f06.png)CloudFormation 自定义资源

在上图中，当您在 CloudFormation 模板中使用自定义资源时，将发生以下步骤：

1.  您需要在 CloudFormation 模板中定义自定义资源。自定义资源具有`AWS::CloudFormation::CustomResource`资源类型，或者是`Custom::<resource-name>`。当 CloudFormation 遇到自定义资源时，它会查找一个名为`ServiceToken`的特定属性，该属性提供应该配置自定义资源的 Lambda 函数的 ARN。

1.  CloudFormation 调用 Lambda 函数，并以 JSON 对象的形式将自定义资源请求传递给函数。事件具有请求类型，该类型定义了请求是创建、更新还是删除资源，并包括请求属性，这些属性是您可以在自定义资源定义中定义的自定义属性，将传递给 Lambda 函数。请求的另一个重要属性是响应 URL，它提供了一个预签名的 S3 URL，Lambda 函数应在配置完成后向其发布响应。

1.  Lambda 函数处理自定义资源请求，并根据请求类型和请求属性执行资源的适当配置。配置完成后，函数向自定义资源请求中收到的响应 URL 发布成功或失败的响应，并在创建或更新资源时包含资源标识符。假设响应信号成功，响应可能包括`Data`属性，该属性可以包含有关已配置的自定义资源的有用信息，可以在 CloudFormation 堆栈的其他位置使用标准的`!Sub ${<resource-name>.<data-property>}`语法引用，其中`<data-property>`是响应的`Data`属性中包含的属性。

1.  云形成服务轮询响应 URL 以获取响应。一旦收到响应，CloudFormation 解析响应并继续堆栈配置（或在响应指示失败的情况下回滚堆栈）。

# 创建自定义资源 Lambda 函数

如前一节所讨论的，自定义资源需要您创建一个 Lambda 函数，该函数处理 CloudFormation 发送的传入事件，执行自定义配置操作，然后使用预签名的 S3 URL 响应 CloudFormation。

这听起来相当复杂，但是有许多可用的工具可以使这在相对简单的用例中成为可能，如以下示例所示。

```
...
...
Resources:
 EcsTaskRunner:
 Type: AWS::Lambda::Function
    DependsOn:
 - EcsTaskRunnerLogGroup
 Properties:
 FunctionName: !Sub ${AWS::StackName}-ecsTasks
 Description: !Sub ${AWS::StackName} ECS Task Runner
 Handler: index.handler
 MemorySize: 128
 Runtime: python3.6
 Timeout: 300
      Role: !Sub ${EcsTaskRunnerRole.Arn}
 Code:
 ZipFile: |
 import cfnresponse
 import boto3

 client = boto3.client('ecs')

 def handler(event, context):
 try:
              print("Received event %s" % event)
              if event['RequestType'] == 'Delete':
                cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, event['PhysicalResourceId'])
                return
              tasks = client.run_task(
                cluster=event['ResourceProperties']['Cluster'],
                taskDefinition=event['ResourceProperties']['TaskDefinition'],
                overrides=event['ResourceProperties'].get('Overrides',{}),
                count=1,
                startedBy=event['RequestId']
              )
              task = tasks['tasks'][0]['taskArn']
              print("Started ECS task %s" % task)
              waiter = client.get_waiter('tasks_stopped')
              waiter.wait(
                cluster=event['ResourceProperties']['Cluster'],
                tasks=[task],
              )
              result = client.describe_tasks(
                cluster=event['ResourceProperties']['Cluster'],
                tasks=[task]
              )
              exitCode = result['tasks'][0]['containers'][0]['exitCode']
              if exitCode > 0:
                print("ECS task %s failed with exit code %s" % (task, exitCode))
                cfnresponse.send(event, context, cfnresponse.FAILED, {}, task)
              else:
                print("ECS task %s completed successfully" % task)
                cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, task)
            except Exception as e:
              print("A failure occurred with exception %s" % e)
              cfnresponse.send(event, context, cfnresponse.FAILED, {})
 EcsTaskRunnerRole:
 Type: AWS::IAM::Role
 Properties:
 AssumeRolePolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Effect: Allow
 Principal:
 Service: lambda.amazonaws.com
 Action:
 - sts:AssumeRole
 Policies:
 - PolicyName: EcsTaskRunnerPermissions
 PolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Sid: EcsTasks
 Effect: Allow
 Action:
 - ecs:DescribeTasks
 - ecs:ListTasks
 - ecs:RunTask
 Resource: "*"
 Condition:
 ArnEquals:
 ecs:cluster: !Sub ${ApplicationCluster.Arn}
 - Sid: ManageLambdaLogs
 Effect: Allow
 Action:
 - logs:CreateLogStream
 - logs:PutLogEvents
 Resource: !Sub ${EcsTaskRunnerLogGroup.Arn}
 EcsTaskRunnerLogGroup:
 Type: AWS::Logs::LogGroup
 Properties:
 LogGroupName: !Sub /aws/lambda/${AWS::StackName}-ecsTasks
 RetentionInDays: 7
  ApplicationService:
    Type: AWS::ECS::Service
...
...
```

使用 CloudFormation 创建内联 Lambda 函数

前面示例中最重要的方面是`EcsTaskRunner`资源中的`Code.ZipFile`属性，它定义了一个内联 Python 脚本，执行自定义资源的自定义配置操作。请注意，这种内联定义代码的方法通常不推荐用于实际用例，稍后我们将创建一个更复杂的自定义资源，其中包括自己的 Lambda 函数代码的源代码库，但为了保持这个示例简单并介绍自定义资源的核心概念，我现在使用了内联方法。

# 理解自定义资源函数代码

让我们专注于讨论自定义资源函数代码，我已经在之前的示例中将其隔离，并添加了注释来描述各种语句的作用。

```
# Generates an appropriate CloudFormation response and posts to the pre-signed S3 URL
import cfnresponse
# Imports the AWS Python SDK (boto3) for interacting with the ECS service
import boto3

# Create a client for interacting with the ECS service
client = boto3.client('ecs')

# Lambda functions require a handler function that is passed an event and context object
# The event object contains the CloudFormation custom resource event
# The context object contains runtime information about the Lambda function
def handler(event, context):
  # Wrap the code in a try/catch block to ensure any exceptions generate a failure
  try:
    print("Received event %s" % event)
    # If the request is to Delete the resource, simply return success
    if event['RequestType'] == 'Delete':
      cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, event.get('PhysicalResourceId'))
      return
    # Run the ECS task
    # http://boto3.readthedocs.io/en/latest/reference/services/ecs.html#ECS.Client.run_task
    # Requires 'Cluster', 'TaskDefinition' and optional 'Overrides' custom resource properties
    tasks = client.run_task(
      cluster=event['ResourceProperties']['Cluster'],
      taskDefinition=event['ResourceProperties']['TaskDefinition'],
      overrides=event['ResourceProperties'].get('Overrides',{}),
      count=1,
      startedBy=event['RequestId']
    )
    # Extract the ECS task ARN from the return value from the run_task call
    task = tasks['tasks'][0]['taskArn']
    print("Started ECS task %s" % task)

    # Creates a waiter object that polls and waits for ECS tasks to reached a stopped state
    # http://boto3.readthedocs.io/en/latest/reference/services/ecs.html#waiters
    waiter = client.get_waiter('tasks_stopped')
    # Wait for the task ARN that was run earlier to stop
    waiter.wait(
      cluster=event['ResourceProperties']['Cluster'],
      tasks=[task],
    )
    # After the task has stopped, get the status of the task
    # http://boto3.readthedocs.io/en/latest/reference/services/ecs.html#ECS.Client.describe_tasks
    result = client.describe_tasks(
      cluster=event['ResourceProperties']['Cluster'],
      tasks=[task]
    )
    # Get the exit code of the container that ran
    exitCode = result['tasks'][0]['containers'][0]['exitCode']
    # Return failure for non-zero exit code, otherwise return success
    # See https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html for more details on cfnresponse module
    if exitCode > 0:
      print("ECS task %s failed with exit code %s" % (task, exitCode))
      cfnresponse.send(event, context, cfnresponse.FAILED, {}, task)
```

```
else:
      print("ECS task %s completed successfully" % task)
      cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, task)
  except Exception as e:
    print("A failure occurred with exception %s" % e)
    cfnresponse.send(event, context, cfnresponse.FAILED, {})
```

使用 CloudFormation 创建内联 Lambda 函数

在高层次上，自定义资源函数接收 CloudFormation 自定义资源事件，并调用 AWS Python SDK 中 ECS 服务的`run_task`方法，传入 ECS 集群、ECS 任务定义和可选的覆盖以执行。然后函数等待任务完成，检查 ECS 任务的结果，以确定相关容器是否成功完成，然后向 CloudFormation 响应成功或失败。

注意，函数导入了一个名为`cfnresponse`的模块，这是 AWS Lambda Python 运行时环境中包含的一个模块，提供了一个简单的高级机制来响应 CloudFormation 自定义资源请求。函数还导入了一个名为`boto3`的模块，它提供了 AWS Python SDK，并用于创建一个与 ECS 服务专门交互的`client`对象。然后 Lambda 函数定义了一个名为`handler`的函数，这是传递给 Lambda 函数的新事件的入口点，并注意`handler`函数必须接受包含 CloudFormation 自定义资源事件的`event`对象和提供有关 Lambda 环境的运行时信息的`context`对象。请注意，函数应该只尝试运行 CloudFormation 创建和更新请求的任务，并且当接收到删除自定义资源的请求时，可以简单地返回成功，因为任务是短暂的资源。

前面示例中的代码绝不是生产级代码，并且已经简化为仅处理与成功和失败相关的两个主要场景以进行演示。

# 了解自定义资源 Lambda 函数资源

现在您了解了 Lambda 函数代码的实际工作原理，让我们专注于您在之前示例中添加的配置的其余部分。

`EcsTaskRunner`资源定义了 Lambda 函数，其中描述了关键配置属性：

+   `FunctionName`：函数的名称。要理解的一个重要方面是，用于存储函数日志的关联 CloudWatch 日志组必须遵循`/aws/lambda/<function-name>`的命名约定，您会看到`FunctionName`属性与`EcsTaskRunnerLogGroup`资源的`LogGroupName`属性匹配。请注意，`EcsTaskRunner`还必须声明对`EcsTaskRunnerLogGroup`资源的依赖性，根据`DependsOn`设置的配置。

+   `处理程序`：指定 Lambda 函数的入口点，格式为`<module>.<function>`。请注意，当使用模块创建的内联代码机制时，用于 Lambda 函数的模块始终被称为`index`。

+   `超时`：重要的是要理解，目前 Lambda 的最长超时时间为五分钟（300 秒），这意味着您的函数必须在五分钟内完成，否则它们将被终止。Lambda 函数的默认超时时间为 3 秒，因为部署新的 ECS 任务，运行 ECS 任务并等待任务完成需要时间，因此将此超时时间增加到最大超时时间为 300 秒。

+   `角色`：定义要分配给 Lambda 函数的 IAM 角色。请注意，引用的`EcsTaskRunnerRole`资源必须信任 lambda.amazonaws.com，而且至少每个 Lambda 函数必须具有权限写入关联的 CloudWatch 日志组，如果您想要捕获任何日志。ECS 任务运行器函数需要权限来运行和描述 ECS 任务，并且使用条件配置为仅向堆栈中定义的 ECS 集群授予这些权限。

# 创建自定义资源

现在你的自定义资源 Lambda 函数和相关的支持资源都已经就位，你可以定义实际的自定义资源对象。对于我们的用例，我们需要定义一个自定义资源，它将在我们的应用容器中运行`python3 manage.py migrate`命令，并且由于迁移任务与应用数据库交互，任务必须配置各种数据库环境变量，以定义与应用数据库资源的连接。

一种方法是利用之前创建的`ApplicationTaskDefinition`资源，并指定一个命令覆盖，但一个问题是`ApplicationTaskDefinition`包括`collectstatic`容器，我们并不真的想在运行迁移时运行它。为了克服这个问题，你需要创建一个名为`MigrateTaskDefinition`的单独任务定义，它只包括一个特定运行数据库迁移的容器定义：

```
...
...
Resources:
 MigrateTaskDefinition:
    Type: AWS::ECS::TaskDefinition
 Properties:
 Family: todobackend-migrate
 ContainerDefinitions:
 - Name: migrate
 Image: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/docker-in-aws/todobackend:${ApplicationImageTag}
 MemoryReservation: 5
 Cpu: 5
 Environment:
 - Name: DJANGO_SETTINGS_MODULE
 Value: todobackend.settings_release
 - Name: MYSQL_HOST
 Value: !Sub ${ApplicationDatabase.Endpoint.Address}
 - Name: MYSQL_USER
 Value: todobackend
 - Name: MYSQL_PASSWORD
 Value: !Ref DatabasePassword
 - Name: MYSQL_DATABASE
 Value: todobackend
```

```
Command: 
 - python3
 - manage.py
 - migrate
 - --no-input
 LogConfiguration:
 LogDriver: awslogs
 Options:
 awslogs-group: !Sub /${AWS::StackName}/ecs/todobackend
 awslogs-region: !Ref AWS::Region
 awslogs-stream-prefix: docker
  EcsTaskRunner:
    Type: AWS::Lambda::Function
...
...

```

创建迁移任务定义

在上面的例子中，注意到`MigrateTaskDefinition`资源需要配置与数据库相关的环境变量，但不需要你之前在`ApplicationTaskDefinition`资源中配置的卷映射或端口映射。

有了这个任务定义，你现在可以创建你的自定义资源，就像下面的例子所示：

```
...
...
Resources:
 MigrateTask:
 Type: AWS::CloudFormation::CustomResource
 DependsOn:
 - ApplicationAutoscaling
 - ApplicationDatabase
 Properties:
 ServiceToken: !Sub ${EcsTaskRunner.Arn}
 Cluster: !Ref ApplicationCluster
 TaskDefinition: !Ref MigrateTaskDefinition MigrateTaskDefinition:
     Type: AWS::ECS::TaskDefinition
   ...
   ...
   ApplicationService:
    Type: AWS::ECS::Service
    DependsOn:
      - ApplicationAutoscaling
      - ApplicationLogGroup
      - ApplicationLoadBalancerHttpListener
 - MigrateTask
```

```
Properties:
...
...
```

创建迁移任务自定义资源

在上面的例子中，注意到你的自定义资源是用`AWS::CloudFormation::CustomResource`类型创建的，你创建的每个自定义资源都必须包括`ServiceToken`属性，它引用了相关自定义资源 Lambda 函数的 ARN。其余的属性是特定于你的自定义资源函数的，对于我们的情况，至少必须指定要执行的任务的目标 ECS 集群和 ECS 任务定义。注意，自定义资源包括依赖关系，以确保它只在`ApplicationAutoscaling`和`ApplicationDatabase`资源创建后运行，你还需要在本章前面创建的`ApplicationService`资源上添加一个依赖关系，以便在`MigrateTask`自定义资源成功完成之前不会创建或更新此资源。

# 部署自定义资源

现在，您可以使用`aws cloudformation deploy`命令部署您的更改。在 CloudFormation 堆栈更改部署时，一旦 CloudFormation 启动创建自定义资源并调用您的 Lambda 函数，您可以导航到 AWS Lambda 控制台查看您的 Lambda 函数，并检查函数日志。

CloudFormation 自定义资源在最初工作时可能会耗费大量时间，特别是如果您的代码抛出异常并且没有适当的代码来捕获这些异常并发送失败响应。您可能需要等待几个小时才能超时，因为您的自定义资源抛出了异常并且没有返回适当的失败响应给 CloudFormation。

以下屏幕截图演示了在 AWS Lambda 控制台中查看从 CloudFormation 堆栈创建的`todobackend-ecsTasks` Lambda 函数：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/eb137671-2741-4ba2-8634-1079e75d3526.png)在 AWS 控制台中查看 Lambda 函数

在上面的屏幕截图中，**配置**选项卡提供了有关函数的配置详细信息，甚至包括内联代码编辑器，您可以在其中查看、测试和调试您的代码。**监控**选项卡提供了对函数的各种指标的访问权限，并包括一个有用的**跳转到日志**链接，该链接可以直接带您到 CloudWatch 日志中函数的日志：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6adc9b11-80cc-4199-b42f-94ef997e1f74.png)在 AWS 控制台中查看 Lambda 函数日志

在上面的屏幕截图中，START 消息指示函数何时被调用，并且您可以看到生成了一个状态为 SUCCESS 的响应体，该响应体被发布到 CloudFormation 自定义资源响应 URL。

现在是审查 ECS 任务的 CloudWatch 日志的好时机——显示了**/todobackend/ecs/todobackend**日志组，这是在您的 CloudFormation 堆栈中配置的日志组，用于收集应用程序的所有 ECS 任务日志。请注意，有几个日志流 - 一个用于生成静态任务的**collectstatic**容器，一个用于运行迁移的**migrate**容器，以及一个用于主要 todobackend 应用程序的日志流。请注意，每个日志流的末尾都包括 ECS 任务 ID - 这些直接对应于您使用 ECS 控制台或 AWS CLI 与之交互的 ECS 任务 ID：

ECS CloudWatch 日志组

# 验证应用程序

作为最后的检查，示例应用程序现在应该是完全功能的 - 例如，之前失败的待办事项链接现在应该可以工作，如下面的截图所示。

您可以与 API 交互以添加或删除待办事项，并且所有待办事项现在将持久保存在应用程序数据库中，该数据库在您的堆栈中定义：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/98dcd51c-619f-4fde-bab1-95f5526d88bb.png)Working todobackend application

# 总结

在本章中，您成功地将示例 Docker 应用程序部署到 AWS 使用 ECS。您学会了如何定义关键的支持应用程序和基础设施资源，包括如何使用 AWS RDS 服务创建应用程序数据库，以及如何将您的 ECS 应用程序与 AWS 弹性负载均衡服务提供的应用程序负载均衡器集成。

有了这些支持资源，您学会了如何创建控制容器运行时配置的 ECS 任务定义，然后通过为示例应用程序创建 ECS 服务来部署您的 ECS 任务定义的实例。您学会了 ECS 任务定义如何定义卷和多个容器定义，并且您使用了这个功能来创建一个单独的非必要容器定义，每当部署您的 ECS 任务定义时，它总是运行并为示例应用程序生成静态网页文件。您还将示例应用程序的 ECS 服务与堆栈中的各种应用程序负载均衡器资源集成，确保可以跨多个 ECS 服务实例进行负载均衡连接到您的应用程序。

尽管您能够成功将应用程序部署为 ECS 服务，但您发现您的应用程序并不完全功能，因为尚未运行为应用程序数据库建立架构和表的数据库迁移。您通过创建 ECS 任务运行器 CloudFormation 自定义资源来解决了这个问题，这使您能够在每次应用程序部署时运行迁移作为单次任务。自定义资源被定义为一个简单的用 Python 编写的 Lambda 函数，它首先在给定的 ECS 集群上为给定的 ECS 任务定义运行任务，等待任务完成，然后根据与任务相关联的容器的退出代码报告任务的成功或失败。

有了这个自定义资源，您的示例应用现在已经完全可用，尽管它仍然存在一些不足之处。在下一章中，我们将解决其中一个不足之处——保密管理和确保密码保持机密——这在安全的、生产级别的 Docker 应用中至关重要。

# 问题

1.  真/假：RDS 实例需要您创建至少两个子网的 DB 子网组。

1.  在配置应用负载均衡器时，哪个组件服务于来自最终用户的前端连接？

1.  真/假：在创建应用负载均衡器监听器之前，目标组可以接受来自目标的注册。

1.  在配置允许应用数据库和 ECS 容器实例之间访问的安全组规则时，您收到了关于循环依赖的 CloudFormation 错误。您可以使用哪种类型的资源来克服这个问题？

1.  您配置了一个包括两个容器定义的 ECS 任务定义。其中一个容器定义执行一个短暂的配置任务然后退出。您发现 ECS 不断地基于这个任务定义重新启动 ECS 服务。您如何解决这个问题？

1.  您可以配置哪个 CloudFormation 参数来定义对其他资源的显式依赖关系？

1.  真/假：CloudFormation 自定义资源使用 AWS Lambda 函数执行自定义的配置任务。

1.  在接收 CloudFormation 自定义资源事件时，您需要处理哪三种类型的事件？

1.  您创建了一个带有内联 Python 函数的 Lambda 函数，用于执行自定义的配置任务，但是当尝试查看该函数的日志时，没有任何内容被写入 CloudWatch 日志。您确认日志组名称已正确配置给该函数。出现这个问题最可能的原因是什么？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   CloudFormation RDS 实例资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html)

+   CloudFormation 应用负载均衡器资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html)

+   CloudFormation 应用负载均衡监听器资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html)

+   CloudFormation 应用负载均衡目标组资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html)

+   CloudFormation ECS 任务定义资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-taskdefinition.html)

+   CloudFormation ECS 服务资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html)

+   CloudFormation Lambda 函数资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html)

+   CloudFormation Lambda 函数代码：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html)

+   CloudFormation 自定义资源文档：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html)

+   CloudFormation 自定义资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref.html)


# 第九章：管理秘密

秘密管理是现代应用程序和系统的关键安全和运营要求。诸如用户名和密码之类的凭据通常用于验证对可能包含私人和敏感数据的资源的访问，因此非常重要的是，您能够实现一个能够以安全方式向您的应用程序提供这些凭据的秘密管理解决方案，而不会将它们暴露给未经授权的方。 

基于容器的应用程序的秘密管理具有挑战性，部分原因是容器的短暂性质以及在一次性和可重复基础设施上运行容器的基本要求。长期存在的服务器已经过去了，您可以在本地文件中存储秘密 - 现在您的服务器是可以来来去去的 ECS 容器实例，并且您需要一些机制能够在运行时动态地将秘密注入到您的应用程序中。我们迄今为止在本书中使用的一个天真的解决方案是使用环境变量直接将您的秘密注入到您的应用程序中；然而，这种方法被认为是不安全的，因为它经常会通过各种运营数据源以纯文本形式暴露您的秘密。一个更健壮的解决方案是实现一个安全的凭据存储，您的应用程序可以以安全的方式动态检索其秘密 - 然而，设置您自己的凭据存储可能会很昂贵、耗时，并引入重大的运营开销。

在本章中，您将实现一个简单而有效的秘密管理解决方案，由两个关键的 AWS 服务提供支持 - AWS Secrets Manager 和密钥管理服务或 KMS。这些服务将为您提供一个基于云的安全凭据存储，易于管理、成本效益，并且完全集成了标准的 AWS 安全控制，如 IAM 策略和角色。您将学习如何将支持通过环境变量进行配置的任何应用程序与您的秘密管理解决方案集成，方法是在您的 Docker 映像中创建一个入口脚本，该脚本使用 AWS CLI 动态地检索和安全地注入秘密到您的内部容器环境中，并且还将学习如何在使用 CloudFormation 部署您的环境时，将秘密暴露给 CloudFormation 堆栈中的其他资源。

以下主题将被涵盖：

+   创建 KMS 密钥

+   使用 AWS Secrets Manager 创建秘密

+   在容器启动时注入秘密

+   使用 CloudFormation 提供秘密

+   将秘密部署到 AWS

# 技术要求

以下列出了完成本章所需的技术要求：

+   对 AWS 帐户具有管理员访问权限

+   根据第三章的说明配置本地 AWS 配置文件

+   AWS CLI 版本 1.15.71 或更高版本

+   第八章需要完成，并成功部署示例应用程序到 AWS

以下 GitHub URL 包含本章中使用的代码示例 - [`github.com/docker-in-aws/docker-in-aws/tree/master/ch9`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch9)。

查看以下视频以查看代码的实际操作：

[`bit.ly/2LzpEY2`](http://bit.ly/2LzpEY2)

# 创建 KMS 密钥

任何秘密管理解决方案的关键构建块是使用加密密钥加密您的凭据，这确保了您的凭据的隐私和保密性。AWS 密钥管理服务（KMS）是一项托管服务，允许您创建和控制加密密钥，并提供了一个简单、低成本的解决方案，消除了许多管理加密密钥的操作挑战。KMS 的关键功能包括集中式密钥管理、符合许多行业标准、内置审计和与其他 AWS 服务的集成。

在构建使用 AWS Secrets Manager 的秘密管理解决方案时，您应该在本地 AWS 帐户和区域中创建至少一个 KMS 密钥，用于加密您的秘密。AWS 确实提供了一个默认的 KMS 密钥，您可以在 AWS Secrets Manager 中使用，因此这不是一个严格的要求，但是一般来说，根据您的安全要求，您应该能够创建自己的 KMS 密钥。

您可以使用 AWS 控制台和 CLI 轻松创建 KMS 密钥，但是为了符合采用基础设施即代码的一般主题，我们将使用 CloudFormation 创建一个新的 KMS 密钥。

以下示例演示了在新的 CloudFormation 模板文件中创建 KMS 密钥和 KMS 别名，您可以将其放在 todobackend-aws 存储库的根目录下，我们将其称为`kms.yml`：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: KMS Keys

Resources:
  KmsKey:
    Type: AWS::KMS::Key
    Properties:
      Description: Custom key for Secrets
      Enabled: true
      KeyPolicy:
        Version: "2012-10-17"
        Id: key-policy
        Statement: 
          - Sid: Allow root account access to key
            Effect: Allow
            Principal:
              AWS: !Sub arn:aws:iam::${AWS::AccountId}:root
            Action:
              - kms:*
            Resource: "*"
  KmsKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: alias/secrets-key
      TargetKeyId: !Ref KmsKey

```

```
Outputs:
  KmsKey:
    Description: Secrets Key KMS Key ARN
    Value: !Sub ${KmsKey.Arn}
    Export:
      Name: secrets-key
```

使用 CloudFormation 创建 KMS 资源

在前面的例子中，您创建了两个资源——一个名为`KmsKey`的`AWS::KMS::Key`资源，用于创建新的 KMS 密钥，以及一个名为`KmsKeyAlias`的`AWS::KMS::Alias`资源，用于为密钥创建别名或友好名称。

`KmsKey`资源包括一个`KeyPolicy`属性，该属性定义了授予根帐户对密钥访问权限的资源策略。这是您创建的任何 KMS 密钥的要求，以确保您始终至少有一些方法访问密钥，您可能已经使用该密钥加密了有价值的数据，如果密钥不可访问，这将给业务带来相当大的成本。 

如果您通过 AWS 控制台或 CLI 创建 KMS 密钥，根帐户访问策略将自动为您创建。

在前面的示例中，CloudFormation 模板的一个有趣特性是创建了一个 CloudFormation 导出，每当您将`Export`属性添加到 CloudFormation 输出时就会创建。在前面的示例中，`KmsKey`输出将`Value`属性指定的`KmsKey`资源的 ARN 导出，而`Export`属性创建了一个 CloudFormation 导出，您可以在其他 CloudFormation 堆栈中引用它，以注入导出的值，而不必明确指定导出的值。稍后在本章中，您将看到如何利用这个 CloudFormation 导出，所以如果现在还不太明白，不用担心。

有了前面示例中的配置，假设您已经将此模板放在名为`kms.yml`的文件中，现在可以部署新的堆栈，这将导致创建新的 KMS 密钥和 KMS 资源：

```
> export AWS_PROFILE=docker-in-aws
> aws cloudformation deploy --template-file kms.yml --stack-name kms
Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga:

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - kms
> aws cloudformation list-exports
{
    "Exports": [
        {
            "ExportingStackId": "arn:aws:cloudformation:us-east-1:385605022855:stack/kms/be0a6d20-3bd4-11e8-bf63-50faeaabf0d1",
            "Name": "secrets-key",
            "Value": "arn:aws:kms:us-east-1:385605022855:key/ee08c380-153c-4f31-bf72-9133b41472ad"
        }
    ]
}
```

使用 CloudFormation 部署 KMS 密钥

在前面的例子中，在创建 CloudFormation 堆栈之后，请注意`aws cloudformation list-exports`命令现在列出了一个名为`secrets-key`的单个导出。此导出的值是您堆栈中 KMS 密钥资源的 ARN，您现在可以在其他 CloudFormation 堆栈中使用`Fn::ImportValue`内部函数来导入此值，只需简单地引用`secrets-key`的导出名称（例如，`Fn::ImportValue: secrets-key`）。

在使用 CloudFormation 导出时要小心。这些导出是用于引用静态资源的，您导出的值在未来永远不会改变。一旦另一个堆栈引用了 CloudFormation 导出，您就无法更改该导出的值，也无法删除导出所属的资源或堆栈。CloudFormation 导出对于诸如 IAM 角色、KMS 密钥和网络基础设施（例如 VPC 和子网）等静态资源非常有用，一旦实施后就不会改变。

# 使用 KMS 加密和解密数据

现在您已经创建了一个 KMS 密钥，您可以使用这个密钥来加密和解密数据。

以下示例演示了使用 AWS CLI 加密简单纯文本值：

```
> aws kms encrypt --key-id alias/secrets-key --plaintext "Hello World"
{
    "CiphertextBlob": "AQICAHifCoHWAYb859mOk+pmJ7WgRbhk58UL9mhuMIcVAKJ18gHN1/SRRhwQVoVJvDS6i7MoAAAAaTBnBgkqhkiG9w0BBwagWjBYAgEAMFMGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMYm4au5zNZG9wa5ceAgEQgCZdADZyWKTcwDfTpw60kUI8aIAtrECRyW+/tu58bYrMaZFlwVYmdA==",
    "KeyId": "arn:aws:kms:us-east-1:385605022855:key/ee08c380-153c-4f31-bf72-9133b41472ad"
}
```

使用 KMS 密钥加密数据

在上面的示例中，请注意您必须使用`--key-id`标志指定 KMS 密钥 ID 或别名，并且每当使用 KMS 密钥别名时，您总是要使用`alias/<alias-name>`作为前缀。加密数据以 Base64 编码的二进制块形式返回到`CiphertextBlob`属性中，这也方便地将加密的 KMS 密钥 ID 编码到加密数据中，这意味着 KMS 服务可以解密密文块，而无需您明确指定加密的 KMS 密钥 ID：

```
> ciphertext=$(aws kms encrypt --key-id alias/secrets-key --plaintext "Hello World" --query CiphertextBlob --output text)
> aws kms decrypt --ciphertext-blob fileb://<(echo $ciphertext | base64 --decode)
{
    "KeyId": "arn:aws:kms:us-east-1:385605022855:key/ee08c380-153c-4f31-bf72-9133b41472ad",
    "Plaintext": "SGVsbG8gV29ybGQ="
}
```

使用 KMS 密钥解密数据

在上面的示例中，您加密了一些数据，这次使用 AWS CLI 查询和文本输出选项来捕获`CiphertextBlob`属性值，并将其存储在名为`ciphertext`的 bash 变量中。然后，您使用`aws kms decrypt`命令将密文作为二进制文件传递，使用 bash 进程替换将密文的 Base64 解码值传递到二进制文件 URI 指示器（`fileb://`）中。请注意，返回的`Plaintext`值不是您最初加密的`Hello World`值，这是因为`Plaintext`值是以 Base64 编码格式，下面的示例进一步使用`aws kms decrypt`命令返回原始明文值：

```
> aws kms decrypt --ciphertext-blob fileb://<(echo $ciphertext | base64 --decode) \
    --query Plaintext --output text | base64 --decode
Hello World
```

使用 KMS 密钥解密数据并返回明文值在前两个示例中，`base64 --decode`命令用于解码 MacOS 和大多数 Linux 平台上的 Base64 值。在一些 Linux 平台（如 Alpine Linux）上，`--decode`标志不被识别，您必须使用`base64 -d`命令。

# 使用 AWS Secrets Manager 创建秘密

您已经建立了一个可以用于加密和解密数据的 KMS 密钥，现在您可以将此密钥与 AWS Secrets Manager 服务集成，这是一个在 2018 年 3 月推出的托管服务，可以让您轻松且具有成本效益地将秘密管理集成到您的应用程序中。

# 使用 AWS 控制台创建秘密

尽管在过去的几章中我们专注于通过 CloudFormation 创建 AWS 资源，但不幸的是，在撰写本文时，CloudFormation 不支持 AWS Secrets Manager 资源，因此如果您使用 AWS 工具，您需要通过 AWS 控制台或 AWS CLI 来配置您的秘密。

要通过 AWS 控制台创建新秘密，请从服务列表中选择 AWS Secrets Manager，然后单击**存储新秘密**按钮。选择**其他类型的秘密**作为秘密类型，指定秘密键和值，并选择您在本章前面创建的`secrets-key` KMS 密钥，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/770663ce-e078-403a-ad44-11ed6bd3815f.png)

使用 AWS Secrets Manager 创建新秘密

在前面的示例中，请注意 AWS Secrets Manager 允许您在单个秘密中存储多个键/值对。这很重要，因为您经常希望将秘密注入为环境变量，因此以键/值格式存储秘密允许您将环境变量名称指定为键，将秘密指定为值。

单击下一步后，您可以配置秘密名称和可选描述：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/3000a2a3-9520-40df-b976-da5096b821c8.png)配置秘密名称和描述

在前面的屏幕截图中，您配置了要称为`todobackend/credentials`的秘密，我们将在本章后面用于 todobackend 应用程序。一旦您配置了秘密名称和描述，您可以单击**下一步**，跳过**配置自动轮换**部分，最后单击**存储**按钮以完成秘密的创建。

# 使用 AWS CLI 创建秘密

您还可以使用`aws secretsmanager create-secret`命令通过 AWS CLI 创建秘密：

```
> aws secretsmanager create-secret --name test/credentials --kms-key-id alias/secrets-key \
 --secret-string '{"MYSQL_PASSWORD":"some-super-secret-password"}'
{
    "ARN": "arn:aws:secretsmanager:us-east-1:385605022855:secret:test/credentials-l3JdTI",
    "Name": "test/credentials",
    "VersionId": "beab75bd-e9bc-4ac8-913e-aca26f6e3940"
}
```

使用 AWS CLI 创建秘密

在前面的示例中，请注意您将秘密字符串指定为 JSON 对象，这提供了您之前看到的键/值格式。

# 使用 AWS CLI 检索秘密

您可以使用`aws secretsmanager get-secret-value`命令通过 AWS CLI 检索秘密：

```
> aws secretsmanager get-secret-value --secret-id test/credentials
{
    "ARN": "arn:aws:secretsmanager:us-east-1:385605022855:secret:test/credentials-l3JdTI",
    "Name": "test/credentials",
    "VersionId": "beab75bd-e9bc-4ac8-913e-aca26f6e3940",
    "SecretString": "{\"MYSQL_PASSWORD\":\"some-super-password\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1523605423.133
}
```

使用 AWS CLI 获取秘密值

在本章后面，您将为示例应用程序容器创建一个自定义入口脚本，该脚本将使用上面示例中的命令在启动时将秘密注入到应用程序容器环境中。

# 使用 AWS CLI 更新秘密

回想一下第八章，驱动 todobackend 应用程序的 Django 框架需要配置一个名为`SECRET_KEY`的环境变量，用于各种加密操作。在本章早些时候，当您创建**todobackend/credentials**秘密时，您只为用于数据库密码的`MYSQL_PASSWORD`变量创建了一个键/值对。

让我们看看如何现在更新**todobackend/credentials**秘密以添加`SECRET_KEY`变量的值。您可以通过运行`aws secretsmanager update-secret`命令来更新秘密，引用秘密的 ID 并指定新的秘密值：

```
> aws secretsmanager get-random-password --password-length 50 --exclude-characters "'\""
{
    "RandomPassword": "E2]eTfO~8Z5)&amp;0SlR-&amp;XQf=yA:B(`,p.B#R6d]a~X-vf?%%/wY"
}
> aws secretsmanager update-secret --secret-id todobackend/credentials \
    --kms-key-id alias/secrets-key \
    --secret-string '{
 "MYSQL_PASSWORD":"some-super-secret-password",
 "SECRET_KEY": "E2]eTfO~8Z5)&amp;0SlR-&amp;XQf=yA:B(`,p.B#R6d]a~X-vf?%%/wY"
 }'
{
    "ARN": "arn:aws:secretsmanager:us-east-1:385605022855:secret:todobackend/credentials-f7AQlO",
    "Name": "todobackend/credentials",
    "VersionId": "cd258b90-d108-4a06-b0f2-849be15f9c33"
}
```

使用 AWS CLI 更新秘密值

在上面的例子中，请注意您可以使用`aws secretsmanager get-random-password`命令为您生成一个随机密码，这对于`SECRET_KEY`变量非常理想。重要的是，您要使用`--exclude-characters`排除引号和引号字符，因为这些字符通常会导致处理这些值的 bash 脚本出现问题。

然后运行`aws secretsmanager update-secret`命令，指定正确的 KMS 密钥 ID，并提供一个更新的 JSON 对象，其中包括`MYSQL_PASSWORD`和`SECRET_KEY`键/值对。

# 使用 AWS CLI 删除和恢复秘密

可以通过运行`aws secretsmanager delete-secret`命令来删除秘密，如下例所示：

```
> aws secretsmanager delete-secret --secret-id test/credentials
{
    "ARN": "arn:aws:secretsmanager:us-east-1:385605022855:secret:test/credentials-l3JdTI",
    "Name": "test/credentials",
    "DeletionDate": 1526198116.323
}
```

使用 AWS CLI 删除秘密值

请注意，AWS Secrets Manager 不会立即删除您的秘密，而是在 30 天内安排删除该秘密。在此期间，该秘密是不可访问的，但可以在安排的删除日期之前恢复，如下例所示：

```
> aws secretsmanager delete-secret --secret-id todobackend/credentials
{
    "ARN": "arn:aws:secretsmanager:us-east-1:385605022855:secret:todobackend/credentials-f7AQlO",
    "Name": "todobackend/credentials",
    "DeletionDate": 1526285256.951
}
> aws secretsmanager get-secret-value --secret-id todobackend/credentials
An error occurred (InvalidRequestException) when calling the GetSecretValue operation: You can’t perform this operation on the secret because it was deleted.

> aws secretsmanager restore-secret --secret-id todobackend/credentials
{
    "ARN": "arn:aws:secretsmanager:us-east-1:385605022855:secret:todobackend/credentials-f7AQlO",
    "Name": "todobackend/credentials"
}

> aws secretsmanager get-secret-value --secret-id todobackend/credentials \
 --query SecretString --output text
```

```
{
  "MYSQL_PASSWORD":"some-super-secret-password",
  "SECRET_KEY": "E2]eTfO~8Z5)&amp;0SlR-&amp;XQf=yA:B(`,p.B#R6d]a~X-vf?%%/wY"
}
```

使用 AWS CLI 恢复秘密值

您可以看到，在删除秘密后，您无法访问该秘密，但是一旦使用`aws secretsmanager restore-secret`命令恢复秘密，您就可以再次访问您的秘密。

# 在容器启动时注入秘密

在 Docker 中管理秘密的一个挑战是以安全的方式将秘密传递给容器。

下图说明了一种有些天真但可以理解的方法，即使用环境变量直接注入你的秘密作为明文值，这是我们在第八章中采取的方法：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b8598acf-a39f-4589-a201-c349a97e31bd.png)通过环境变量注入密码

这种方法简单易配置和理解，但从安全角度来看并不被认为是最佳实践。当你采用这种方法时，你可以通过检查 ECS 任务定义来以明文查看你的凭据，如果你在 ECS 容器实例上运行`docker inspect`命令，你也可以以明文查看你的凭据。你也可能无意中使用这种方法记录你的秘密，这可能会无意中与未经授权的第三方共享，因此显然这种方法并不被认为是良好的实践。

另一种被认为更安全的替代方法是将你的秘密存储在安全的凭据存储中，并在应用程序启动时或在需要秘密时检索秘密。AWS Secrets Manager 就是一个提供这种能力的安全凭据存储的示例，显然这是我们在本章将重点关注的解决方案。

当你将你的秘密存储在安全的凭据存储中，比如 AWS Secrets Manager 时，你有两种一般的方法来获取你的秘密，如下图所示：

+   **应用程序注入秘密：** 采用这种方法，你的应用程序包括直接与凭据存储进行接口的支持。在这里，你的应用程序可能会寻找一个静态名称的秘密，或者可能会通过环境变量注入秘密名称。在 AWS Secrets Manager 的示例中，这意味着你的应用代码将使用 AWS SDK 来进行适当的 API 调用，以从 AWS Secrets Manager 检索秘密值。

+   **Entrypoint 脚本注入秘密：**使用这种方法，您可以将应用程序需要的秘密的名称配置为标准环境变量，然后在应用程序之前运行 entrypoint 脚本，从 AWS Secrets Manager 中检索秘密，并将它们作为环境变量注入到内部容器环境中。尽管这听起来与在 ECS 任务定义级别配置环境变量的方法类似，但不同之处在于这发生在容器内部，而外部配置的环境变量应用后，这意味着它们不会暴露给 ECS 控制台或`docker inspect`命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/1f2b0532-b097-4637-861e-d3492194ff46.png)使用凭据存储存储和检索密码

应用程序注入秘密的方法通常从安全角度被认为是最佳方法，但这需要应用程序明确支持与您使用的凭据存储进行交互，这意味着需要额外的开发和成本来支持这种方法。

entrypoint 脚本方法被认为不太安全，因为您在应用程序外部暴露了一个秘密，但秘密的可见性仅限于容器本身，不会在外部可见。使用 entrypoint 脚本确实提供了一个好处，即不需要应用程序专门支持与凭据存储进行交互，使其成为为大多数组织提供运行时秘密的更通用解决方案，而且足够安全，这是我们现在将要关注的方法。

# 创建一个 entrypoint 脚本

Docker 的`ENTRYPOINT`指令配置了容器执行的第一个命令或脚本。当与`CMD`指令一起配置时，`ENTRYPOINT`命令或脚本被执行，`CMD`命令作为参数传递给`entrypoint`脚本。这建立了一个非常常见的模式，即 entrypoint 执行初始化任务，例如将秘密注入到环境中，然后根据传递给脚本的命令参数调用应用程序。

以下示例演示了为 todobackend 示例应用程序创建 entrypoint 脚本，您应该将其放在 todobackend 存储库的根目录中：

```
> pwd
/Users/jmenga/Source/docker-in-aws/todobackend
> touch entrypoint.sh > tree -L 1 .
├── Dockerfile
├── Makefile
├── docker-compose.yml
├── entrypoint.sh
└── src

1 directory, 4 files
```

在 Todobackend 存储库中创建一个 entrypoint 脚本

以下示例显示了入口脚本的内容，该脚本将从 AWS Secrets Manager 中注入秘密到环境中：

```
#!/bin/bash
set -e -o pipefail

# Inject AWS Secrets Manager Secrets
# Read space delimited list of secret names from SECRETS environment variable
echo "Processing secrets [${SECRETS}]..."
read -r -a secrets <<< "$SECRETS"
for secret in "${secrets[@]}"
do
  vars=$(aws secretsmanager get-secret-value --secret-id $secret \
    --query SecretString --output text \
    | jq -r 'to_entries[] | "export \(.key)='\''\(.value)'\''"')
  eval "$vars"
done

# Run application
exec "$@"
```

定义一个将秘密注入到环境中的入口脚本

在前面的例子中，从`SECRETS`环境变量创建了一个名为`secrets`的数组，该数组预计以空格分隔的格式包含一个或多个秘密的名称，这些秘密应该被处理。例如，您可以通过在示例中演示的方式设置`SECRETS`环境变量来处理名为`db/credentials`和`app/credentials`的两个秘密：

```
> export SECRETS="db/credentials app/credentials"
```

定义多个秘密

回顾前面的例子，然后脚本通过循环遍历数组中的每个秘密，使用`aws secretsmanager get-secret-value`命令获取每个秘密的`SecretString`值，然后将每个值传递给`jq`实用程序，将`SecretString`值解析为 JSON 对象，并生成一个 shell 表达式，将每个秘密键和值导出为环境变量。请注意，`jq`表达式涉及大量的转义，以确保特殊字符被解释为文字，但这个表达式的本质是为凭据中的每个键值对输出`export *key*='*value*'`。

为了进一步理解这一点，您可以在命令行上使用您之前创建的`todobackend/credentials`秘钥运行相同的命令：

```
> aws secretsmanager get-secret-value --secret-id todobackend/credentials \
 --query SecretString --output text \
 | jq -r 'to_entries[] | "export \(.key)='\''\(.value)'\''"'
export MYSQL_PASSWORD='some-super-secret-password'
export SECRET_KEY='E2]eTfO~8Z5)&amp;0SlR-&amp;XQf=yA:B(`,p.B#R6d]a~X-vf?%%/wY'
```

生成一个将秘钥导出到环境中的 Shell 表达式

在前面的例子中，请注意输出是您将执行的单独的`export`命令，以将秘密键值对注入到环境中。每个环境变量值也被单引号引起来，以确保 bash 将所有特殊字符视为文字值。

回顾前面的例子，在 for 循环中的`eval $vars`语句简单地将生成的导出语句作为 shell 命令进行评估，这导致每个键值对被注入到本地环境中。

在单独的变量中捕获`aws secretsmanager ...`命令替换的输出，可以确保任何在此命令替换中发生的错误将被传递回您的入口脚本。您可能会尝试在 for 循环中只运行一个`eval $(aws secretsmanager ..)`语句，但采用这种方法意味着如果`aws secretsmanager ...`命令替换退出并出现错误，您的入口脚本将不会意识到这个错误，并且将继续执行，这可能会导致应用程序出现奇怪的行为。

循环完成后，最终的`exec "$@"`语句将控制权交给传递给入口脚本的参数，这些参数由特殊的`$@` shell 变量表示。例如，如果您的入口脚本被调用为`entrypoint python3 manage.py migrate --noinput`，那么`$@` shell 变量将保存参数`python3 manage.py migrate --noinput`，最终的`exec`命令将启动并将控制权交给`python3 manage.py migrate --noinput`命令。

在容器入口脚本中使用`exec "$@"`方法非常重要，因为`exec`确保容器的父进程成为传递给入口点的命令参数。如果您没有使用`exec`，只是运行命令，那么运行脚本的父 bash 进程将保持为容器的父进程，并且在停止容器时，bash 进程（而不是您的应用程序）将接收到后续的信号以终止容器。通常希望您的应用程序接收这些信号，以便在终止之前优雅地清理。

# 向 Dockerfile 添加入口脚本

现在，您已经在 todobackend 存储库中建立了一个入口脚本，您需要将此脚本添加到现有的 Dockerfile，并确保使用`ENTRYPOINT`指令指定脚本作为入口点：

```
...
...
# Release stage
FROM alpine
LABEL=todobackend

# Install operating system dependencies
RUN apk add --no-cache python3 mariadb-client bash curl bats jq && \
 pip3 --no-cache-dir install awscli

# Create app user
RUN addgroup -g 1000 app && \
    adduser -u 1000 -G app -D app

# Copy and install application source and pre-built dependencies
COPY --from=test --chown=app:app /build /build
COPY --from=test --chown=app:app /app /app
RUN pip3 install -r /build/requirements.txt -f /build --no-index --no-cache-dir
RUN rm -rf /build

# Create public volume
RUN mkdir /public
RUN chown app:app /public
VOLUME /public

# Entrypoint script
COPY entrypoint.sh /usr/bin/entrypoint
RUN chmod +x /usr/bin/entrypoint
ENTRYPOINT ["/usr/bin/entrypoint"]

# Set working directory and application user
WORKDIR /app
USER app
```

向 Dockerfile 添加入口脚本

在前面的例子中，请注意您修改第一个`RUN`指令以确保安装了 AWS CLI，方法是添加`pip3 --no-cache install awscli`命令。

最后，您将入口脚本复制到`/usr/bin/entrypoint`，确保脚本具有可执行标志，并将脚本指定为镜像的入口点。请注意，您必须以 exec 样式格式配置`ENTRYPOINT`指令，以确保您在容器中运行的命令作为参数传递给入口脚本（请参阅[`docs.docker.com/engine/reference/builder/#cmd`](https://docs.docker.com/engine/reference/builder/#cmd)中的第一个注释）。

现在您的 Dockerfile 已更新，您需要提交更改，重新构建并发布 Docker 镜像更改，如下例所示：

```
> git add -A
> git commit -a -m "Add entrypoint script"
[master 5fdbe62] Add entrypoint script
 4 files changed, 31 insertions(+), 7 deletions(-)
 create mode 100644 entrypoint.sh
> export AWS_PROFILE=docker-in-aws
> make login
$(aws ecr get-login --no-include-email)
Login Succeeded
> make test && make release docker-compose build --pull release
Building release
Step 1/28 : FROM alpine AS test
latest: Pulling from library/alpine...
...
docker-compose run app bats acceptance.bats
Starting todobackend_db_1 ... done
Processing secrets []...
1..4
ok 1 todobackend root
ok 2 todo items returns empty list
ok 3 create todo item
ok 4 delete todo item
App running at http://localhost:32784
> make publish docker-compose push release
Pushing release (385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest)...
The push refers to repository [385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend]
fdc98d6948f6: Pushed
9f33f154b3fa: Pushed
d8aedb2407c9: Pushed
f778da37eed6: Pushed
05e5971d2995: Pushed
4932bb9f39a5: Pushed
fa63544c9f7e: Pushed
fd3b38ee8bd6: Pushed
cd7100a72410: Layer already exists
latest: digest: sha256:5d456c61dd23728ec79c281fe5a3c700370382812e75931b45f0f5dd1a8fc150 size: 2201
Pushing app (385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:5fdbe62)...
The push refers to repository [385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend]
fdc98d6948f6: Layer already exists
9f33f154b3fa: Layer already exists
d8aedb2407c9: Layer already exists
f778da37eed6: Layer already exists
05e5971d2995: Layer already exists
4932bb9f39a5: Layer already exists
fa63544c9f7e: Layer already exists
fd3b38ee8bd6: Layer already exists
cd7100a72410: Layer already exists
34d86eb: digest: sha256:5d456c61dd23728ec79c281fe5a3c700370382812e75931b45f0f5dd1a8fc150 size: 2201
```

发布更新的 Docker 镜像

在上面的示例中，当 Docker 镜像发布时，请注意应用程序服务的 Docker 标签（在我的示例中为`5fdbe62`，实际哈希值会因人而异），您可以从第一章中回忆起，它指定了源代码库的 Git 提交哈希。您将在本章后面需要此标签，以确保您可以部署您的更改到在 AWS 中运行的 todobackend 应用程序。

# 使用 CloudFormation 提供秘密

您已在 AWS Secrets Manager 中创建了一个秘密，并已添加了支持使用入口脚本将秘密安全地注入到容器中的功能。请记住，入口脚本会查找一个名为`SECRETS`的环境变量，而您 CloudFormation 模板中的`ApplicationTaskDefinition`和`MigrateTaskDefinition`资源目前正在直接注入应用程序数据库。为了支持在您的堆栈中使用秘密，您需要配置 ECS 任务定义，以包括`SECRETS`环境变量，并配置其名称为您的秘密名称，并且您还需要确保您的容器具有适当的 IAM 权限来检索和解密您的秘密。

另一个考虑因素是您的`ApplicationDatabase`资源的密码是如何配置的——目前配置为使用堆栈参数输入的密码；但是，您的数据库现在需要能够以某种方式从您新创建的秘密中获取其密码。

# 配置 ECS 任务定义以使用秘密

首先要处理重新配置 ECS 任务定义以使用您新创建的秘密。您的容器现在包括一个入口脚本，该脚本将从 AWS Secrets Manager 中检索秘密，并且在更新各种 ECS 任务定义以将您的秘密名称导入为环境变量之前，您需要确保您的容器具有执行此操作的正确权限。虽然您可以将此类权限添加到应用于 EC2 实例级别的 ECS 容器实例角色，但更安全的方法是创建特定的 IAM 角色，您可以将其分配给您的容器，因为您可能会与多个应用程序共享 ECS 集群，并且不希望从在集群上运行的任何容器中授予对您秘密的访问权限。

ECS 包括一个名为 IAM 任务角色的功能（[`docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)），它允许您在 ECS 任务定义级别授予 IAM 权限，并且在我们只想要将对 todobackend 秘密的访问权限授予 todobackend 应用程序的情况下非常有用。以下示例演示了创建授予这些特权的 IAM 角色：

```
...
...
Resources:
  ...
  ...
  ApplicationTaskRole:
 Type: AWS::IAM::Role
 Properties:
 AssumeRolePolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Effect: Allow
 Principal:
 Service: ecs-tasks.amazonaws.com
 Action:
 - sts:AssumeRole
 Policies:
 - PolicyName: SecretsManagerPermissions
 PolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Sid: GetSecrets
 Effect: Allow
 Action:
 - secretsmanager:GetSecretValue
 Resource: !Sub arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:todobackend/*
 - Sid: DecryptSecrets
 Effect: Allow
 Action:
 - kms:Decrypt
 Resource: !ImportValue secrets-key
  ApplicationTaskDefinition:
    Type: AWS::ECS::TaskDefinition
...
...
```

创建 IAM 任务角色

在前面的示例中，您创建了一个名为`ApplicationTaskRole`的新资源，其中包括一个`AssumeRolePolicyDocument`属性，该属性定义了可以承担该角色的受信任实体。请注意，这里的主体是`ecs-tasks.amazonaws.com`服务，这是您的容器在尝试使用 IAM 角色授予的权限访问 AWS 资源时所假定的服务上下文。该角色包括一个授予`secretsmanager:GetSecretValue`权限的策略，这允许您检索秘密值，这个权限被限制为所有以`todobackend/`为前缀命名的秘密的 ARN。如果您回顾一下之前的示例，当您通过 AWS CLI 创建了一个测试秘密时，您会发现秘密的 ARN 包括 ARN 末尾的随机值，因此您需要在 ARN 中使用通配符，以确保您具有权限，而不考虑这个随机后缀。请注意，该角色还包括对`secrets-key` KMS 密钥的`Decrypt`权限，并且您使用`!ImportValue`或`Fn::ImportValue`内部函数来导入您在第一个示例中导出的 KMS 密钥的 ARN。

有了`ApplicationTaskRole`资源，以下示例演示了如何重新配置`stack.yml`文件中的`todobackend-aws`存储库中的`ApplicationTaskDefinition`和`MigrateTaskDefinition`资源：

```
Parameters:
  ...
  ...
  ApplicationSubnets:
    Type: List<AWS::EC2::Subnet::Id>
    Description: Target subnets for EC2 instances
 # The DatabasePassword parameter has been removed
  VpcId:
    Type: AWS::EC2::VPC::Id
    Description: Target VPC
 ...
  ... 
Resources:
  ...
  ...
  MigrateTaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: todobackend-migrate
 TaskRoleArn: !Sub ${ApplicationTaskRole.Arn}
      ContainerDefinitions:
        - Name: migrate
          Image: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/docker-in-aws/todobackend:${ApplicationImageTag}
          MemoryReservation: 5
          Cpu: 5
          Environment:
            - Name: DJANGO_SETTINGS_MODULE
              Value: todobackend.settings_release
            - Name: MYSQL_HOST
              Value: !Sub ${ApplicationDatabase.Endpoint.Address}
            - Name: MYSQL_USER
              Value: todobackend
            - Name: MYSQL_DATABASE
              Value: todobackend
            # The MYSQL_PASSWORD variable has been removed
 - Name: SECRETS
 Value: todobackend/credentials
            - Name: AWS_DEFAULT_REGION
              Value: !Ref AWS::Region  ...
  ...
  ApplicationTaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: todobackend
 TaskRoleArn: !Sub ${ApplicationTaskRole.Arn}
      Volumes:
        - Name: public
      ContainerDefinitions:
        - Name: todobackend
          Image: !Sub ${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/docker-in-aws/todobackend:${ApplicationImageTag}
          MemoryReservation: 395
          Cpu: 245
          MountPoints:
            - SourceVolume: public
              ContainerPath: /public
          Environment:- Name: DJANGO_SETTINGS_MODULE
              Value: todobackend.settings_release
            - Name: MYSQL_HOST
              Value: !Sub ${ApplicationDatabase.Endpoint.Address}
            - Name: MYSQL_USER
              Value: todobackend
            - Name: MYSQL_DATABASE
              Value: todobackend
 # The MYSQL_PASSWORD and SECRET_KEY variables have been removed            - Name: SECRETS
 Value: todobackend/credentials
            - Name: AWS_DEFAULT_REGION
              Value: !Ref AWS::Region
...
...
```

配置 ECS 任务定义以使用秘密

在上面的示例中，您配置每个任务定义使用 IAM 任务角色通过`TaskRoleArn`属性，该属性引用了您在上一个示例中创建的`ApplicationTaskRole`资源。接下来，您添加新入口脚本在您的 Docker 镜像中期望的`SECRETS`环境变量，并删除先前从 AWS Secrets Manager 服务中检索的`MYSQL_PASSWORD`和`SECRET_KEY`变量。请注意，您需要包括一个名为`AWS_DEFAULT_REGION`的环境变量，因为这是 AWS CLI 所需的，以确定您所在的区域。

因为您不再将数据库密码作为参数注入到堆栈中，您还需要更新 todobackend-aws 存储库中的`dev.cfg`文件，并且还要指定您在之前示例中发布的更新的 Docker 镜像标记：

```
ApplicationDesiredCount=1
ApplicationImageId=ami-ec957491
ApplicationImageTag=5fdbe62
ApplicationSubnets=subnet-a5d3ecee,subnet-324e246f
VpcId=vpc-f8233a80
```

更新输入参数

在上面的示例中，`DatabasePassword=my-super-secret-password`行已被删除，并且`ApplicationImageTag`参数的值已被更新，引用了您新更新的 Docker 镜像上标记的提交哈希。

# 向其他资源公开秘密

您已更新了 ECS 任务定义，使您的应用容器现在将从 AWS Secrets Manager 中提取秘密并将它们注入为环境变量。这对于您的 Docker 镜像效果很好，因为您可以完全控制您的镜像的行为，并且可以添加诸如入口脚本之类的功能来适当地注入秘密。对于依赖这些秘密的其他资源，您没有这样的能力，例如，您堆栈中的`ApplicationDatabase`资源定义了一个 RDS 实例，截至撰写本文时，它不包括对 AWS Secrets Manager 的本地支持。

解决这个问题的一个方法是创建一个 CloudFormation 自定义资源，其工作是查询 AWS Secrets Manager 服务并返回与给定秘密相关的秘密值。因为自定义资源可以附加数据属性，所以您可以在其他资源中引用这些属性，提供一个简单的机制将您的秘密注入到任何不原生支持 AWS Secrets Manager 的 CloudFormation 资源中。如果您对这种方法的安全性有疑问，CloudFormation 自定义资源响应规范（[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref-responses.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref-responses.html)）包括一个名为`NoEcho`的属性，该属性指示 CloudFormation 不通过控制台或日志信息公开数据属性。通过设置此属性，您可以确保您的秘密不会因查询 CloudFormation API 或审查 CloudFormation 日志而无意中暴露。

# 创建一个 Secrets Manager Lambda 函数

以下示例演示了向您的 CloudFormation 堆栈添加一个 Lambda 函数资源，该函数查询 AWS Secrets Manager 服务，并返回给定秘密名称和秘密值内键/值对中的目标键的秘密值：

```
...
...
Resources:
  SecretsManager:
 Type: AWS::Lambda::Function
 DependsOn:
 - SecretsManagerLogGroup
 Properties:
 FunctionName: !Sub ${AWS::StackName}-secretsManager
 Description: !Sub ${AWS::StackName} Secrets Manager
 Handler: index.handler
 MemorySize: 128
 Runtime: python3.6
 Timeout: 300
 Role: !Sub ${SecretsManagerRole.Arn}
 Code:
 ZipFile: |
 import cfnresponse, json, sys, os
 import boto3

 client = boto3.client('secretsmanager')

 def handler(event, context):
            sys.stdout = sys.__stdout__
 try:
 print("Received event %s" % event)
 if event['RequestType'] == 'Delete':
 cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, event['PhysicalResourceId'])
 return
 secret = client.get_secret_value(
 SecretId=event['ResourceProperties']['SecretId'],
 )
 credentials = json.loads(secret['SecretString'])
              # Suppress logging output to ensure credential values are kept secure
              with open(os.devnull, "w") as devnull:
                sys.stdout = devnull
                cfnresponse.send(
                  event, 
                  context, 
                  cfnresponse.SUCCESS,
                  credentials, # This dictionary will be exposed to CloudFormation resources
                  secret['VersionId'], # Physical ID of the custom resource
                  noEcho=True
                )
 except Exception as e:
 print("A failure occurred with exception %s" % e)
 cfnresponse.send(event, context, cfnresponse.FAILED, {})
 SecretsManagerRole:
 Type: AWS::IAM::Role
 Properties:
 AssumeRolePolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Effect: Allow
 Principal:
 Service: lambda.amazonaws.com
 Action:
 - sts:AssumeRole
 Policies:
 - PolicyName: SecretsManagerPermissions
 PolicyDocument:
 Version: "2012-10-17"
 Statement:
 - Sid: GetSecrets
 Effect: Allow
 Action:
 - secretsmanager:GetSecretValue
 Resource: !Sub arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:todobackend/*
            - Sid: DecryptSecrets
              Effect: Allow
              Action:
 - kms:Decrypt
 Resource: !ImportValue secrets-key
- Sid: ManageLambdaLogs
 Effect: Allow
 Action:
 - logs:CreateLogStream
 - logs:PutLogEvents
 Resource: !Sub ${SecretsManagerLogGroup.Arn}
```

```
SecretsManagerLogGroup:
 Type: AWS::Logs::LogGroup
 Properties:
 LogGroupName: !Sub /aws/lambda/${AWS::StackName}-secretsManager
 RetentionInDays: 7...
  ...
```

添加一个 Secrets Manager CloudFormation 自定义资源函数

前面示例的配置与您在第八章中执行的配置非常相似，当时您创建了`EcsTaskRunner`自定义资源函数。在这里，您创建了一个`SecretsManager` Lambda 函数，配有一个关联的`SecretsManagerRole` IAM 角色，该角色授予了从 AWS Secrets Manager 检索和解密密钥的能力，类似于之前创建的`ApplicationTaskRole`，以及一个`SecretsManagerLogGroup`资源，用于收集来自 Lambda 函数的日志。

函数代码比 ECS 任务运行器代码更简单，期望传递一个名为 `SecretId` 的属性给自定义资源，该属性指定秘密的 ID 或名称。函数从 AWS Secrets Manager 获取秘密，然后使用 `json.loads` 方法将秘密键值对加载为名为 `credentials` 的 JSON 对象变量。然后，函数将 `credentials` 变量返回给 CloudFormation，这意味着每个凭据都可以被堆栈中的其他资源访问。请注意，您使用 `with` 语句来确保由 `cfnresponse.send` 方法打印的响应数据被抑制，通过将 `sys.stdout` 属性设置为 `/dev/null`，因为响应数据包含您不希望以明文形式暴露的秘密值。这种方法需要一些小心，您需要在 `handler` 方法的开头将 `sys.stdout` 属性恢复到其默认状态（由 `sys.__stdout__` 属性表示），因为您的 Lambda 函数运行时可能会在多次调用之间被缓存。

自定义资源函数代码可以扩展到将秘密部署到 AWS Secrets Manager。例如，您可以将预期的秘密值的 KMS 加密值作为输入，甚至生成一个随机的秘密值，然后部署和公开此凭据给其他资源。

# 创建一个秘密自定义资源

现在您已经为自定义资源准备了一个 Lambda 函数，您可以创建实际的自定义资源，该资源将提供对存储在 AWS Secrets Manager 中的秘密的访问。以下示例演示了在本章前面创建的 **todobackend/credentials** 密钥的自定义资源，然后从您的 `ApplicationDatabase` 资源中访问该密钥：

```
...
...
Resources:
  Secrets:
 Type: AWS::CloudFormation::CustomResource
 Properties:
 ServiceToken: !Sub ${SecretsManager.Arn}
 SecretId: todobackend/credentials
  SecretsManager:
    Type: AWS::Lambda::FunctionResources:
  ...
  ...
  ApplicationDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: MySQL
      EngineVersion: 5.7
      DBInstanceClass: db.t2.micro
      AllocatedStorage: 10
      StorageType: gp2
      MasterUsername: todobackend
 MasterUserPassword: !Sub ${Secrets.MYSQL_PASSWORD} ...
  ...
```

添加一个 Secrets Manager 自定义资源

在前面的示例中，您创建了一个名为 `Secrets` 的自定义资源，它通过 `ServiceToken` 属性引用 `SecretsManager` 函数，然后通过 `SecretId` 属性传递要检索的凭据的名称。然后，现有的 `ApplicationDatabase` 资源上的 `MasterUserPassword` 属性被更新为引用通过 `Secrets` 资源可访问的 `MYSQL_PASSWORD` 键，该键返回存储在 **todobackend/credentials** 密钥中的正确密码值。

# 将秘密部署到 AWS

此时，您已准备好部署对 CloudFormation 堆栈的更改，您可以使用我们在过去几章中使用的`aws cloudformation deploy`命令来执行：

```
> aws cloudformation deploy --template-file stack.yml \
 --stack-name todobackend --parameter-overrides $(cat dev.cfg) \
 --capabilities CAPABILITY_NAMED_IAM

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - todobackend
```

部署 CloudFormation 堆栈更改

部署将影响以下资源：

+   支持自定义资源的资源将首先被创建，同时将应用于 ECS 任务定义的更改。

+   名为`Secrets`的自定义资源将被创建，一旦创建，将公开**todobackend/credentials**密钥的键/值对给其他 CloudFormation 资源。

+   `ApplicationDatabase`资源将被更新，`MasterPassword`属性将根据**todobackend/credentials**密钥中`MYSQL_PASSWORD`变量的值进行更新。

+   `MigrateTask`自定义资源将根据与关联的`MigrateTaskDefinition`的更改进行更新，并运行一个新任务，该任务使用更新后的 todobackend 镜像中的入口脚本将**todobackend/credentials**密钥中的每个键/值对导出到环境中，其中包括访问应用程序数据库所需的`MYSQL_PASSWORD`变量。

+   `ApplicationService`资源将根据与关联的`ApplicationTaskDefinition`的更改进行更新，并且类似于`MigrateTask`，每个应用程序实例现在在启动时将注入与**todobackend/credentials**密钥相关的环境变量。更新将触发`ApplicationService`的滚动部署，这将使新版本的应用程序投入使用，然后排空和移除旧版本的应用程序，而不会造成任何中断。

假设部署成功，您应该能够验证应用程序仍然成功运行，并且可以列出、添加和删除待办事项。

您还应该验证您的`SecretsManagerFunction`资源未记录秘密的明文值—以下屏幕截图显示了此功能的日志输出，并且您可以看到它抑制了发送回 CloudFormation 的成功响应的日志记录：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/25145a22-a7df-45d4-bf25-3c5f3a9aa41b.png)查看 Secrets Manager 功能的日志输出

# 摘要

秘密管理对于短暂的 Docker 应用程序来说是一个挑战，其中预先配置的长时间运行的服务器并不再是一个选项，因为凭据存储在配置文件中，直接将密码作为外部配置的环境变量注入被认为是一种糟糕的安全实践。这需要一个秘密管理解决方案，使您的应用程序可以动态地从安全凭据存储中获取秘密，在本章中，您成功地使用 AWS Secrets Manager 和 KMS 服务实现了这样的解决方案。

您学会了如何创建 KMS 密钥，用于加密和解密机密信息，并由 AWS Secrets Manager 使用，以确保其存储的秘密的隐私和保密性。接下来，您将介绍 AWS Secrets Manager，并学习如何使用 AWS 控制台和 AWS CLI 创建秘密。您学会了如何在秘密中存储多个键/值对，并介绍了诸如删除保护之类的功能，其中 AWS Secrets Manager 允许您在 30 天内恢复先前删除的秘密。

有了样本应用程序的凭据存储位置，您学会了如何在容器中使用入口点脚本，在容器启动时动态获取和注入秘密值，使用简单的 bash 脚本与 AWS CLI 结合，将一个或多个秘密值作为变量注入到内部容器环境中。尽管这种方法被认为比应用程序直接获取秘密不太安全，但它的优势在于可以应用于支持环境变量配置的任何应用程序，使其成为一个更加通用的解决方案。

在为您的应用程序发布更新的 Docker 镜像后，您更新了 ECS 任务定义，以注入每个容器应检索的秘密的名称，然后创建了一个简单的自定义资源，能够将您的秘密暴露给不支持 AWS Secrets Manager 的其他类型的 AWS 资源，并且没有机制（如容器入口点脚本）来检索秘密。您确保配置了此自定义资源，以便它不会通过日志或其他形式的操作事件透露您的凭据，并更新了应用程序数据库资源，以通过此自定义资源检索应用程序的数据库密码。

有了一个安全管理解决方案，您已经解决了前几章的核心安全问题，在下一章中，您将学习如何解决应用程序的另一个安全问题，即能够独立隔离网络访问并在每个容器或 ECS 任务定义基础上应用网络访问规则。

# 问题

1.  真/假：KMS 服务要求您提供自己的私钥信息。

1.  KMS 的哪个特性允许您为密钥指定逻辑名称，而不是基于 UUID 的标识符？

1.  您想避免手动配置在多个 CloudFormation 堆栈中使用的 KMS 密钥的 ARN。假设您在单独的 CloudFormation 堆栈中定义了 KMS 密钥，您可以使用哪个 CloudFormation 功能来解决这个问题？

1.  真/假：当您从 AWS Secrets Manager 中删除一个秘密时，您永远无法恢复该秘密。

1.  在入口脚本中，您通常会使用哪些工具来从 AWS Secrets Manager 检索秘密并将秘密中的键/值对转换为适合导出到容器环境的形式？

1.  在容器入口脚本中收到一个错误，指示您没有足够的权限访问一个秘密。您检查了 IAM 角色，并确认它对该秘密允许了一个单一的`secretsmanager:GetSecretValue`权限。您需要授予哪些其他权限来解决这个问题？

1.  在处理不应公开为明文值的敏感数据时，应设置哪个 CloudFormation 自定义资源属性？

1.  在访问 AWS 资源的容器入口脚本中收到错误消息“您必须配置区域”。您应该向容器添加哪个环境变量？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   CloudFormation KMS 密钥资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-key.html)

+   CloudFormation KMS 别名资源参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-alias.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kms-alias.html)

+   AWS KMS 开发人员指南：[`docs.aws.amazon.com/kms/latest/developerguide/overview.html`](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html)

+   AWS CLI KMS 参考：[`docs.aws.amazon.com/cli/latest/reference/kms/index.html`](https://docs.aws.amazon.com/cli/latest/reference/kms/index.html)

+   AWS Secrets Manager 用户指南：[`docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html`](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)

+   AWS CLI Secrets Manager 参考：[`docs.aws.amazon.com/cli/latest/reference/secretsmanager/index.html`](https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/index.html)

+   AWS Python SDK Secrets Manager 参考：[`boto3.readthedocs.io/en/latest/reference/services/secretsmanager.html`](http://boto3.readthedocs.io/en/latest/reference/services/secretsmanager.html)

+   CloudFormation 导出：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-exports.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-exports.html)

+   Docker Secrets Management 的一般讨论：[`github.com/moby/moby/issues/13490`](https://github.com/moby/moby/issues/13490)
