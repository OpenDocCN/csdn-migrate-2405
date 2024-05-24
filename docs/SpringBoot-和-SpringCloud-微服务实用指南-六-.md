# SpringBoot 和 SpringCloud 微服务实用指南（六）

> 原文：[`zh.annas-archive.org/md5/328F7FCE73118A0BA71B389914A67B52`](https://zh.annas-archive.org/md5/328F7FCE73118A0BA71B389914A67B52)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十七章：作为 Spring Cloud Gateway 的替代品实现 Kubernetes 特性

当前微服务架构包含许多实现大规模微服务架构中所需的重要设计模式的支撑服务；例如边缘、配置和授权服务器，以及分布式跟踪服务。详情请见第一章，*微服务简介*，并参考*微服务设计模式*小节。在前一章中，我们用 Kubernetes 内置的发现服务替换了基于 Netflix Eureka 的服务发现设计模式。在本章中，我们将通过减少需要部署的支撑服务数量来进一步简化微服务架构。相反，相应的设计模式将由 Kubernetes 内置功能处理。Spring Cloud Config Server 将被 Kubernetes 配置映射和机密替换。Spring Cloud Gateway 将被 Kubernetes 入口资源替换，后者可以像 Spring Cloud Gateway 一样充当边缘服务器。

在第十一章中，关于*保护 API 访问安全*，参考*使用 HTTPS 保护外部通信*小节，我们使用证书来保护外部 API。手动处理证书既耗时又容易出错。作为替代方案，我们将介绍 Cert Manager，它可以自动为入口暴露的外部 HTTPS 端点提供新证书并替换已过期的证书。我们将配置`cert-manager`使用**Let's Encrypt**发行证书。Let's Encrypt 是一个可以用来自动颁发证书的免费证书授权机构。Let's Encrypt 必须能够验证我们拥有将发行证书的 DNS 名称。由于我们的 Kubernetes 集群在 Minikube 中本地运行，我们必须让 Let's Encrypt 在配置过程中能够访问我们的集群。我们将使用`ngrok`创建一个从互联网到我们本地 Kubernetes 集群的临时 HTTP 隧道，供 Let's Encrypt 使用。

当使用像 Kubernetes 这样的平台越来越多的特性时，确保微服务的源代码不依赖于该平台是很重要的；也就是说，应该确保微服务在没有 Kubernetes 的情况下仍然可以使用。为了确保我们可以在没有 Kubernetes 的情况下使用微服务，本章将通过使用 Docker Compose 部署微服务架构并以执行`test-em-all.bash`测试脚本结束，验证微服务在没有 Kubernetes 的情况下仍然可以工作。

本章将涵盖以下主题：

+   用 Kubernetes 配置映射和机密替换 Spring Cloud Config Server

+   用 Kubernetes 入口资源替换 Spring Cloud Gateway

+   添加 Cert Manager 以自动提供由 Let's Encrypt 签发的证书

+   使用`ngrok`从互联网建立到我们本地 Kubernetes 集群的 HTTP 隧道。

+   使用 Docker Compose 部署和测试微服务架构，以确保微服务中的源代码不会锁定在 Kubernetes 上。

# 技术要求

本书中描述的所有命令都是在 MacBook Pro 上使用 macOS Mojave 运行的，但修改后可以在其他平台，如 Linux 或 Windows 上运行，应该是很简单的。

本章所需的新工具是命令行`ngrok`工具，用于建立从互联网到我们本地环境的 HTTP 隧道。它可以通过 Homebrew 使用以下命令安装：

```java
brew cask install ngrok
```

要使用`ngrok`，必须创建一个免费账户并注册一个授权令牌，具体步骤如下：

1.  在这里注册：[`dashboard.ngrok.com/signup`](https://dashboard.ngrok.com/signup)。

1.  账户创建后，运行以下命令：

```java
ngrok authtoken <YOUR_AUTH_TOKEN>
```

在这里，`<YOUR_AUTH_TOKEN>`用以下页面找到的授权令牌替换——[`dashboard.ngrok.com/auth`](https://dashboard.ngrok.com/auth)。

本章的源代码可以在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter17`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter17)。

为了能够按照书中描述运行命令，你需要将源代码下载到一个文件夹中，并设置一个环境变量，`$BOOK_HOME`，指向那个文件夹。示例命令如下：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter17
```

Java 源代码是为 Java 8 编写的，并在 Java 12 上进行了测试。本章使用了 Spring Cloud 2.1, SR2（也称为**Greenwich**版本），Spring Boot 2.1.6 和 Spring 5.1.8——这些是编写本章时可用的 Spring 组件的最新版本。源代码已经使用 Kubernetes v1.15 进行了测试。

本章中所有源代码示例均来自`$BOOK_HOME/Chapter17`的源代码，但在某些情况下进行了编辑，去除了源代码中不相关的内容，例如注释、导入和日志语句。

如果你想查看对第十七章中源代码所做的更改，即替换 Spring Cloud Config Server 和 Spring Cloud Gateway 以便使用 Kubernetes 中对应特性的更改，你可以将其与第十六章的源代码进行比较，《将我们的微服务部署到 Kubernetes》。你可以使用你喜欢的`diff`工具，比较`$BOOK_HOME/Chapter16`和`$BOOK_HOME/Chapter17`文件夹。

# 替换 Spring Cloud Config Server。

正如我们在上一章看到的，第十六章，*将我们的微服务部署到 Kubernetes*，在*部署到 Kubernetes*部分，配置映射和秘钥可用于持有我们微服务的配置信息。Spring Cloud Config Server 增加了诸如将所有配置放在一个地方、可选的 Git 版本控制以及加密磁盘上的敏感信息等价值。但它也消耗了相当大的内存（就像任何基于 Java 和 Spring 的应用程序一样）并在启动时增加了显著的开销。例如，当运行本书中使用的自动化集成测试，如测试脚本`test-em-all.bash`时，所有微服务都会同时启动，包括配置服务器。由于其他微服务必须在启动之前从配置服务器获取其配置，它们都必须等待配置服务器启动并运行后才能启动。这导致集成测试运行时出现显著延迟。如果我们使用 Kubernetes 的配置映射和秘钥，则消除了这个延迟，使自动化集成测试运行得更快。在我看来，在底层平台不提供类似功能时使用 Spring Cloud Config Server 是有意义的，但在部署到 Kubernetes 时，最好使用配置映射和秘钥。

使用 Kubernetes 的配置映射和秘钥，而不是 Spring Cloud Config Server，可以加快微服务架构的启动速度，并减少所需内存。它还将通过消除一个支持服务，即配置服务器，简化微服务架构。如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/7ab391b2-00bd-4930-8d8f-371cd083215a.png)

让我们看看替换 Spring Cloud Config Server 所需的步骤！

特别注意，我们只更改了配置；也就是说，不需要更改 Java 源代码！

# 源代码中的更改，以替换 Spring Cloud Config Server

已应用于源代码配置的以下更改，以替换 Spring Cloud Config Server 与 Kubernetes 配置映射和秘钥：

+   删除了项目`spring-cloud/config-server`，还包括：

    +   删除了`settings.gradle`构建文件中的项目。

    +   删除了`config-server`的 YAML 文件及其在`kubernetes/services/base`和`kubernetes/services/overlays/prod`文件夹中的声明。

+   删除了所有微服务中的配置：

    +   删除了`build.gradle`构建文件中的`spring-cloud-starter-config`依赖项。

    +   删除了每个项目`src/main/resource`文件夹中的`bootstrap.yml`文件。

    +   删除了集成测试中的`spring.clod.config.enabled=false`属性设置。

+   `config-repo`文件夹中的配置文件更改：

    +   移除了包含敏感信息的属性，也就是说，MongoDB、MySQL、RabbitMQ 的凭据以及边缘服务器使用的 TLS 证书的密码。它们将被 Kubernetes 密钥替换。

    +   在边缘服务器的配置中移除了对配置服务器 API 的路径

+   `kubernetes/services/base`文件夹中部署资源定义文件的变化：

    +   配置映射作为卷挂载，也就是说，作为容器文件系统中的文件夹。每个微服务都有自己的配置映射，包含适用于特定微服务的配置文件。

    +   定义`SPRING_CONFIG_LOCATION`环境变量以指出卷中的配置文件。

    +   使用密钥定义访问资源管理器的凭据。

大部分变化都在 Kubernetes 部署资源的定义文件中。让我们以`product`微服务的部署资源定义为例来看一下：

```java
apiVersion: apps/v1
kind: Deployment
metadata:
  name: product
spec:
  template:
    spec:
      containers:
      - name: pro
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: "docker"
        - name: SPRING_CONFIG_LOCATION
          value: file:/config-repo/application.yml,file:/config-
           repo/product.yml
        envFrom:
        - secretRef:
            name: rabbitmq-credentials
        - secretRef:
            name: mongodb-credentials
        volumeMounts:
        - name: config-repo-volume
          mountPath: /config-repo
      volumes:
      - name: config-repo-volume
        configMap:
          name: config-repo-product
```

请注意，由于变化未影响到的定义部分被省略以提高可读性。完整的源代码请查看`kubernetes/services/base/product.yml`。

以下解释了前面的源代码：

+   `config-repo-product`配置映射映射在一个名为`config-repo-volume`的卷中。

+   `config-repo-volume`卷挂载在文件系统的`/config-repo`目录下。

+   `SPRING_CONFIG_LOCATION`环境变量告诉 Spring 在哪里可以找到属性文件，在这个例子中，是`/config-repo/application.yml`和`/config-repo/product.yml`文件。

+   访问 RabbitMQ 和 MongoDB 的凭据是基于`rabbitmq-credentials`和`mongodb-credentials`密钥的内容设置为环境变量的。

在*使用 ConfigMaps、密钥和 ingress 进行测试*节中创建 Kubernetes 配置映射和密钥。

替换配置服务器需要的就是这些，接下来的一节中，我们将学习如何用 Kubernetes 的 ingress 资源替换 Spring Cloud Gateway。

# 替换 Spring Cloud Gateway

在本节中，我们将通过用 Kubernetes 内置的 ingress 资源替换 Spring Cloud Gateway，进一步简化微服务架构，减少需要部署的支持服务数量。

如第十五章、*Kubernetes 简介*中介绍的，Kubernetes 中的 ingress 资源可以像 Spring Cloud Gateway 一样作为边缘服务器使用。Spring Cloud Gateway 带有比 ingress 资源更丰富的路由功能。但是 ingress 特性是 Kubernetes 平台的一部分，也可以使用 Cert Manager 自动提供证书，如我们在本章后面所看到的。

我们还使用 Spring Cloud Gateway 保护我们的微服务免受未经验证的请求；也就是说，微服务需要一个来自可信 OAuth 授权服务器或 OIDC 提供者的有效 OAuth 2.0/OIDC 访问令牌。如果需要回顾，请参见第十一章，*保护 API 访问*。通常，Kubernetes 入口资源不支持这一点。然而，入口控制器的特定实现可能会支持它。

最后，我们在第十章，*使用 Spring Cloud Gateway 将微服务隐藏在边缘服务器后面*中向网关添加的综合健康检查可以被每个微服务部署资源中定义的 Kubernetes 存活和就绪探针所替换。对我来说，在底层平台不提供类似功能时使用 Spring Cloud Gateway 是有意义的，但在部署到 Kubernetes 时，最好使用入口资源。

在本章中，我们将验证请求是否包含有效访问令牌的责任委托给`product-composite`微服务。下一章将介绍服务网格的概念，我们将看到一个完全支持验证 JWT 编码访问令牌的入口的替代实现，即我们在本书中使用的访问令牌类型。

在*验证微服务在没有 Kubernetes 的情况下是否工作*部分，我们仍然将使用 Spring Cloud Gateway 和 Docker Compose，所以我们将不会移除项目。

以下图表展示了在将 Spring Cloud Gateway 部署到 Kubernetes 时，如何将其从微服务架构中移除：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/d19dde2e-6974-428d-a6e3-ba564833e00a.png)

让我们看看替换 Spring Cloud Gateway 为 Kubernetes 入口资源需要什么！

特别注意，我们只更改了配置；也就是说，不需要更改 Java 源代码！

# Spring Cloud Gateway 源代码的变化

以下更改已应用于源代码配置，以将 Spring Cloud Gateway 替换为 Kubernetes 入口资源：

+   `kubernetes/services`文件夹中部署资源的变化。

    +   删除了网关的 YAML 文件及其在`base`和`overlays/prod`文件夹中的声明。

    +   在`base/ingress-edge-server.yml`中添加了入口资源，并在`base/kustomization.yml`中对其进行了引用

入口资源的定义如下代码所示：

```java
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: edge
spec:
  tls:
    - hosts:
      - minikube.me
      secretName: tls-certificate
  rules:
  - host: minikube.me
    http:
      paths:
      - path: /oauth
        backend:
          serviceName: auth-server
          servicePort: 80
      - path: /product-composite
        backend:
          serviceName: product-composite
          servicePort: 80 
      - path: /actuator/health
        backend:
          serviceName: product-composite
          servicePort: 80
```

以下是对前面源代码的解释：

+   入口资源的名称为`edge`。

+   `tls`部分指定了入口将需要使用 HTTPS，并且它将使用为`minikube.me`主机名发行的证书。

+   证书存储在一个名为`tls-certificate`的秘密中

    在*使用 Kubernetes ConfigMaps、secrets 和 ingress 资源进行测试*部分的*步骤 4*中创建`tls-certificate`密钥。

+   为请求到`minikube.me`主机名定义路由规则。

    在下一主题中，DNS 名称`minikube.me`将被映射到 Minikube 实例的 IP 地址。

+   为以下内容定义路由：

    +   在`/oauth`路径上的`auth-server`。

    +   在`/product-composite`路径上的`product-composite`微服务。

    +   `product-composite`微服务中的`/actuator/health`路径上的`health`端点。

在下一节中，我们将创建 Kubernetes 的 ingress 资源，并一起测试微服务架构，包括 Kubernetes 的 config maps、secrets 和 ingress 资源。

# 使用 Kubernetes ConfigMaps、secrets 和 ingress 资源进行测试。

在前述更改描述之后，我们准备测试使用 Spring Cloud Config Server 和 Spring Cloud Gateway 替换 Kubernetes config maps、secrets 和 ingress 资源的系统架构。与之前一样，当我们使用 Spring Cloud Gateway 作为边缘服务器时，外部 API 将通过 HTTPS 保护。在此部署中，我们将配置 ingress 资源以重用我们与 Spring Cloud Gateway 一起用于 HTTPS 的自签名证书。以下图表展示了这一点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/5eb38462-0a35-4944-a8e6-0e6ff5e338b1.png)

在下一节中，我们将增强证书使用，并将自签名证书替换为 Let's Encrypt 发行的证书。

ingress 将在 Minikube 实例的默认 HTTPS 端口`443`上暴露。这由我们在执行`minikube addons enable ingress`命令时安装的 ingress 控制器处理；参见第十五章*Kubernetes 简介*，并参考*创建 Kubernetes 集群*部分进行回顾。ingress 控制器由在`kube-system`命名空间中的部署`nginx-ingress-controller`组成。部署使用`hostPort`将其端口`443`映射到宿主机上，即 Minikube 实例中的端口`443`，该端口在容器中运行。部署的定义中的主要部分如下所示：

```java
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx-ingress-controller
spec:
  template:
    spec:
      containers:
        image: quay.io/kubernetes-ingress-controller/nginx-ingress-
         controller:0.23.0
        ports:
        - containerPort: 443
          hostPort: 443
```

此设置适用于用于开发和测试的单节点 Kubernetes 集群。在多节点 Kubernetes 集群中，外部负载均衡器用于暴露高可用性和可伸缩性的 ingress 控制器。

部署使用了与我们在第十六章*部署我们的微服务到 Kubernetes*中使用的相同类型的命令；参考*部署到 Kubernetes 以进行开发和测试*部分。

主要区别是，此部署将：

+   为每个微服务创建一个 config map，而不是为配置服务器创建一个 config map。

+   创建用于资源管理器凭据的秘密和用于 ingress 的 TLS 证书的秘密，而不是创建用于配置服务器凭据的秘密

+   创建一个 Ingress，而不是使用 Spring Cloud Gateway

为了简化部署，已将开发和生产环境的部署脚本添加到源代码中。让我们来看看我们将在此部分使用的开发环境的部署脚本。

# 浏览部署脚本

`kubernetes/scripts/deploy-dev-env.bash`脚本包含了执行部署所需的所有命令。该脚本将执行以下步骤：

1.  它将创建一个配置文件，每个微服务一个。例如，对于`product`微服务，我们有以下内容：

```java
kubectl create configmap config-repo-product --from-file=config-repo/application.yml --from-file=config-repo/product.yml --save-config
```

1.  然后，它将创建所需的秘密。例如，使用以下命令创建访问 RabbitMQ 的凭据：

```java
kubectl create secret generic rabbitmq-credentials \
 --from-literal=SPRING_RABBITMQ_USERNAME=rabbit-user-dev \
 --from-literal=SPRING_RABBITMQ_PASSWORD=rabbit-pwd-dev \
 --save-config
```

1.  也为资源管理器创建了秘密；它们的名称以`server-credentials`结尾。它们在`kubernetes/services/overlays/dev`文件夹的 Kubernetes 定义文件中使用。例如，使用以下命令创建 RabbitMQ 的凭据：

```java
kubectl create secret generic rabbitmq-server-credentials \
 --from-literal=RABBITMQ_DEFAULT_USER=rabbit-user-dev \
 --from-literal=RABBITMQ_DEFAULT_PASS=rabbit-pwd-dev \
 --save-config
```

1.  包含 ingress 的 TLS 证书的秘密`tls-certificate`基于`kubernetes/cert`文件夹中已经存在的自签名证书。它使用以下命令创建：

```java
kubectl create secret tls tls-certificate --key kubernetes/cert/tls.key --cert kubernetes/cert/tls.crt
```

以下命令创建了自签名证书：

`openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout kubernetes/cert/tls.key -out kubernetes/cert/tls.crt -subj "/CN=minikube.me/O=minikube.me"`

1.  基于`dev`覆盖层部署开发环境的微服务，使用`-k`开关激活 Kustomize：

```java
kubectl apply -k kubernetes/services/overlays/dev
```

1.  等待部署及其 pods 运行：

```java
kubectl wait --timeout=600s --for=condition=ready pod --all
```

完成本指南后，我们就可以运行部署和测试所需的命令了！

# 部署和测试命令的运行

在我们能够执行部署之前，需要做以下准备工作：

+   将 ingress 使用的 DNS 名称`minikube.me`映射到 Minikube 实例的 IP 地址

+   从源代码构建 Docker 镜像

+   在 Kubernetes 中创建一个命名空间

运行以下命令以准备、部署和测试：

1.  将`minikube.me`映射到 Minikube 实例的 IP 地址，通过在`/etc/hosts`文件中添加以下命令的行来实现：

```java
sudo bash -c "echo $(minikube ip) minikube.me | tee -a /etc/hosts" 
```

使用`cat /etc/hosts`命令验证结果。预期会出现包含 Minikube 实例 IP 地址后跟`minikube.me`的行，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/e620ccae-5f94-4d2f-a0cc-9c5b94ffb268.png)

1.  使用以下命令从源代码构建 Docker 镜像：

```java
cd $BOOK_HOME/Chapter17
eval $(minikube docker-env)
./gradlew build && docker-compose build
```

1.  重新创建命名空间`hands-on`，并将其设置为默认命名空间：

```java
kubectl delete namespace hands-on
kubectl create namespace hands-on
kubectl config set-context $(kubectl config current-context) --namespace=hands-on 
```

1.  运行以下命令执行部署脚本：

```java
./kubernetes/scripts/deploy-dev-env.bash 
```

1.  部署完成后，使用以下命令启动测试：

```java
HOST=minikube.me PORT=443 ./test-em-all.bash
```

期待我们看到前几章中的正常输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/2029adbf-aead-45bf-b8a5-78f258baa0f6.png)

1.  您可以尝试手动执行早期章节中的相同步骤来测试 API：只需将主机和端口替换为 `minikube.me`。获取 OAuth/OIDC 访问令牌，并使用它调用具有以下命令的 API：

```java
ACCESS_TOKEN=$(curl -k https://writer:secret@minikube.me/oauth/token -d grant_type=password -d username=magnus -d password=password -s | jq .access_token -r)

curl -ks https://minikube.me/product-composite/2 -H "Authorization: Bearer $ACCESS_TOKEN" | jq .productId
```

期待在响应中收到请求的产品 ID，`2`。

本节中设置的部署是基于一个用于开发和测试的环境。如果您想要建立一个用于 staging 和生产的环境，例如在第十六章《将我们的微服务部署到 Kubernetes》中描述的那样，请参考“为 staging 和生产部署到 Kubernetes”部分。为此，您可以使用 `./kubernetes/scripts/deploy-prod-env.bash` 脚本。在第 4 步中像以前概述的那样使用它，而不是 `deploy-dev-env.bash` 脚本。

注意，`deploy-prod-env.bash` 脚本将使用 Docker Compose 启动 MySQL、MongoDB 和 RabbitMQ 的三个资源管理器；也就是说，它们将作为 Docker 容器在 Kubernetes 外运行（正如在第十六章《将我们的微服务部署到 Kubernetes》中所描述的那样）。

此部署使用了一个由 Kubernetes ingress 暴露的自签名证书，该证书需要手动提供。手动处理证书既耗时又容易出错。例如，很容易忘记及时续签一个证书。在下一节中，我们将学习如何使用 Cert Manager 和 Let's Encrypt 来自动化这个提供过程！

# 自动化证书的提供

正如本章介绍中提到的，我们将使用 Cert Manager 来自动化由 ingress 暴露的外部 HTTPS 端点所使用的证书的提供。Cert Manager 将在 Kubernetes 中作为一个附加组件运行，并配置为从 Let's Encrypt 请求免费证书颁发机构的证书，以自动化证书的颁发。为了能够验证我们拥有证书将要颁发的 DNS 名称，Let's Encrypt 要求访问我们要为其颁发证书的端点。由于我们的 Kubernetes 集群在本地运行 Minikube，我们必须让 Let's Encrypt 在证书提供期间能够访问我们的集群。我们将使用 ngrok 工具创建一个从互联网到我们的本地 Kubernetes 集群的临时 HTTP 隧道，供 Let's Encrypt 使用。

有关每个产品的更多信息，请参阅以下内容：

+   Cert Manager: [`docs.cert-manager.io/en/latest/index.html`](http://docs.cert-manager.io/en/latest/index.html)

+   Let's Encrypt: [`letsencrypt.org/docs/`](https://letsencrypt.org/docs/)

+   ngrok: [`ngrok.com/docs`](https://ngrok.com/docs)

所有这一切可能看起来有些令人望而却步，所以让我们一步一步来：

1.  部署证书管理器并在 Kubernetes 中基于 Let's Encrypt 定义发行者。

1.  使用 ngrok 创建 HTTP 隧道。

1.  使用证书管理器（Cert Manager）和让我们加密（Let's Encrypt）提供证书。

1.  验证我们是否从 Let's Encrypt 获取了证书。

1.  清理。

只有当你的 Kubernetes 集群无法通过互联网访问时，才需要 HTTP 隧道。如果其入口资源可以直接从互联网访问，则可以跳过使用 ngrok。

# 部署证书管理器并定义 Let's Encrypt 发行者

要部署证书管理器（Cert Manager），我们可以执行一个 Kubernetes 定义文件，这将创建一个名为 `cert-manager` 的命名空间，然后将证书管理器部署到该命名空间中。我们将安装编写本章时的最新版本 0.8.1。运行以下命令：

```java
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.8.1/cert-manager.yaml
```

如果你收到类似“无法识别 "https://github.com/jetstack/cert-manager/releases/download/v0.8.1/cert-manager.yaml"：在版本 "certmanager.k8s.io/v1alpha1" 中没有找到 "Issuer" 种类”的错误消息，那么只需重新运行命令即可。

等待部署及其 Pod 可用：

```java
kubectl wait --timeout=600s --for=condition=ready pod --all -n cert-manager
```

预期从命令中输出与以下类似的结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/196e1fc3-83ec-4d71-84dc-18e5f84a59ed.png)

有了证书管理器（Cert Manager）之后，我们可以在 Kubernetes 中定义基于 Let's Encrypt 的发行者。

让我们加密（Let's Encrypt）暴露了以下发行者：

+   **开发和测试阶段使用的暂存环境**，可以预期在这一阶段会请求很多短期证书。暂存环境允许创建许多证书，但证书中的根**CA**（证书授权中心）不被信任。这意味着来自暂存环境的证书不能用于保护由网页浏览器使用的网页或 API。当用户打开由暂存环境中的证书保护的网页时，网页浏览器不会信任其根 CA 并抱怨。

+   **生产环境**，它使用一个受信任的根 CA 来颁发证书。因此，它可以用来颁发被网页浏览器信任的证书。生产环境限制了可以颁发的证书数量。例如，每个注册域名每周只能发行 50 个新证书，例如在 `ngrok.io` 的情况下。

我们将在 Kubernetes 中注册两个发行者，一个用于暂存环境，一个用于生产环境。发行者可以在集群全局或命名空间局部注册。为了保持一致性，我们将使用命名空间局部发行者。

在证书提供过程中，证书管理器（Cert Manager）和让我们加密（Let's Encrypt）之间的通信基于一个标准协议，即**自动化证书管理环境 v2**（**ACME v2**）。让我们加密将充当证书授权中心（CA），而证书管理器将充当 ACME 客户端。为了验证 DNS 名称的所有权，ACME 协议规定了 CA 可以使用两种类型的挑战：

+   `http-01`: 认证机构（CA）要求 ACME 客户端在以下 URL 下创建一个随机命名的文件：`http://<domainname>/.well-known/acme-challenge/<randomfilename>`。如果 CA 能够使用这个 URL 成功访问该文件，那么域名所有权得到验证。

+   `dns-01`: 认证机构（CA）要求 ACME 客户端在 DNS 服务器下的域名`_acme-challenge.<YOUR_DOMAIN>`放置一个指定的值。这通常通过 DNS 提供商的 API 来实现。如果 CA 能够在 DNS 服务器中的 TXT 记录中访问到指定的内容，那么域名所有权得到验证。

自动化`dns-01`挑战通常比自动化`http-01`挑战要困难，但在 HTTP 端点不可通过互联网的情况下，它是更优的选择。`dns-01`挑战还支持发行通配符证书，这是`http-01`挑战无法使用的。在本章中，我们将配置 Cert Manager 以使用基于`http-01`的挑战。

对于 Let's Encrypt 测试环境的发行者定义如下：

```java
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: letsencrypt-issuer-staging
spec:
  acme:
    email: <your email address>
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-issuer-staging-account-key
    solvers:
    - http01:
        ingress:
          class: nginx
```

以下解释了前面的源代码：

+   发行者的`name`，`letsencrypt-issuer-staging`，将在负载均衡器中引用发行者时使用，以提供证书。

+   `email`必须填写您的电子邮件地址。Let's Encrypt 将使用该电子邮件地址联系您关于到期的证书和与您账户相关的问题。

+   `server`字段指出了 Let's Encrypt 测试环境的 URL。

+   `privateKeySecretRef`字段包含一个密钥的名字。这个密钥将由 Cert Manager 创建，并将包含一个 ACME/Let's Encrypt `account private key`。这个密钥用来识别您（或您的公司）作为 ACME 服务的用户，即 Let's Encrypt。它用于签署发送到 Let's Encrypt 的请求，以验证您的身份。

+   `solver`定义声明使用`http-01`挑战来验证域名所有权。

对于 Let's Encrypt 生产环境的发行者定义看起来是一样的，主要区别在于使用的 ACME 服务器 URL：[`acme-v02.api.letsencrypt.org/directory`](https://acme-v02.api.letsencrypt.org/directory)。

编辑以下文件，并将`<your email address>`替换为您的电子邮件地址：

+   `kubernetes/services/base/letsencrypt-issuer-staging.yaml`

+   `kubernetes/services/base/letsencrypt-issuer-prod.yaml`

使用以下命令应用定义：

```java
kubectl apply -f kubernetes/services/base/letsencrypt-issuer-staging.yaml
kubectl apply -f kubernetes/services/base/letsencrypt-issuer-prod.yaml
```

现在我们已经有了 Cert Manager，并注册了 Let's Encrypt 测试环境和生产环境的发行者。下一步是使用`ngrok`创建一个 HTTP 隧道。

# 使用 ngrok 创建 HTTP 隧道

`ngrok`的免费订阅可以用来创建一个 HTTP 隧道，其中`ngrok`使用其自己的通配符证书`***.ngrok.io`来终止 HTTPS 流量，也就是说，在 HTTP 请求到达 Kubernetes 中的 ingress 资源之前。发送 HTTPS 请求的客户端只能看到`ngrok`证书，而看不到 Kubernetes 中 ingress 资源暴露的证书。这意味着我们不能使用 HTTP 隧道来测试由 Let's Encrypt 发行并由 Kubernetes 中的 ingress 资源使用的证书。这在以下图表中有所说明：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a5583460-7ef4-4f1a-a566-507395d3be49.png)

但是在提供证书的过程中，可以让 HTTP 隧道来使用，这时 Let's Encrypt 需要验证 ACME 客户端是否拥有它请求颁发证书的 DNS 名称。DNS 名称将是 HTTP 隧道分配给的主机名，例如，`6cc09528.ngrok.io`。一旦完成提供证书的过程，我们可以关闭 HTTP 隧道并将主机名重定向到 Minikube 实例的 IP 地址（使用本地的`/etc/hosts`文件）。这在以下图表中有所说明：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/d42306ac-0d80-43ca-bbc8-f783f35353ed.png)

对于付费客户，`ngrok`提供了一个 TLS 隧道，它通过 HTTPS 流量而不是终止它；也就是说，发送 HTTPS 请求的客户端能够看到并验证 Kubernetes 中 ingress 资源暴露的证书。使用 TLS 隧道而不是 HTTP 隧道应该使这一额外步骤变得 unnecessary。

执行以下步骤以创建 HTTP 隧道：

1.  使用以下命令创建 HTTP 隧道：

```java
ngrok http https://minikube.me:443
```

1.  期望输出类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/cc23906d-f9c7-44e8-aa0d-da848bd6e750.png)

1.  拿起 HTTP 隧道的主机名，例如前面的示例中的`6cc09528.ngrok.io`，并将其保存在一个环境变量中，如下所示：

```java
NGROK_HOST=6cc09528.ngrok.io
```

在 HTTP 隧道就位的情况下，我们可以为使用 Cert Manager 和 Let's Encrypt 自动提供其证书的 ingress 资源的定义做好准备！

# 使用 Cert Manager 和 Let's Encrypt 提供证书

在配置 ingress 资源之前，了解提供证书的高级过程可能会有所帮助。使用 Cert Manager 和 Let's Encrypt 自动提供证书的过程如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ed4a016d-32e6-4381-af09-0f5d93641c42.png)

以下步骤将在提供过程中进行：

1.  创建了一个注有`certmanager.k8s.io/issuer: "name of a Let's Encrypt issuer"`的 ingress。

1.  这个注解将触发 Cert Manager 开始使用 Let's Encrypt 为 ingress 提供证书。

1.  在提供证书的过程中，Let's Encrypt 将执行一个`http-01`挑战，并使用 HTTP 隧道来验证 Cert Manager 拥有 DNS 名称。

1.  一旦配置完成，Cert Manager 将在 Kubernetes 中存储证书，并创建一个由入口指定的名称的秘密。

我们将添加一个新的入口`edge-ngrok`，定义在`ingress-edge-server-ngrok.yml`文件中，它将路由请求到 HTTP 隧道的主机名。这个入口将具有与现有入口相同的路由规则。不同的部分看起来像以下这样：

```java
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: edge-ngrok
  annotations:
    certmanager.k8s.io/issuer: "letsencrypt-issuer-staging"
spec:
  tls:
  - hosts:
    - xxxxxxxx.ngrok.io
    secretName: tls-ngrok-letsencrypt-certificate
  rules:
  - host: xxxxxxxx.ngrok.io
```

以下是对前面源代码的解释：

+   使用`certmanager.k8s.io/issuer: "letsencrypt-issuer-staging"`注解，我们请求 Cert Manager 使用名为`letsencrypt-issuer-staging`的发行版为这个入口配置证书。

+   `tls`和`rules`声明中的`xxxxxxxx.ngrok.io`主机名必须用你的 HTTP 隧道实际主机名替换。

+   一旦配置完成，证书将被存储在名为`tls-ngrok-letsencrypt-certificate`的秘密中。

在深入了解配置过程的高级层面并准备好使用它的入口资源之后，我们可以开始使用 Let's Encrypt 支持的两个环境来配置证书。首先从适合开发和测试活动的 staging 环境开始。

# 使用 Let's Encrypt 的 staging 环境

执行以下步骤从 Let's Encrypt 的 staging 环境配置证书并验证它是否工作：

1.  编辑`kubernetes/services/base/ingress-edge-server-ngrok.yml`文件，并将`xxxxxxxx.ngrok.io`用你的 HTTP 隧道的主机名替换两次！

    （之前的示例中的`6cc09528.ngrok.io`。）

1.  在启动配置之前，在另一个终端窗口中运行一个 watch 命令来监控证书的配置。运行以下命令：

```java
kubectl get cert --watch
```

1.  通过以下命令应用新的入口定义来启动配置：

```java
kubectl apply -f kubernetes/services/base/ingress-edge-server-ngrok.yml
```

1.  Cert Manager 现在将检测到新的入口并开始使用由`ngrok`设置的 HTTP 隧道通过 ACME v2 协议提供 Let's Encrypt staging 环境的证书。

1.  过了一会儿，你应该注意到在运行 HTTP 隧道的终端窗口中出现了`http-01`挑战。预期输出中将有一个像以下的请求：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/48532285-e42c-41b8-87c5-953c433986d2.png)

1.  将创建一个`tls-ngrok-letsencrypt-certificate`证书，并将其存储在`tls-ngrok-letsencrypt-certificate`秘密中，如入口指定。预期`kubectl get cert --watch`命令的输出将与以下类似：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/75548aa6-b6b1-4b86-b7f3-24a40a679869.png)

1.  过了一会儿，证书的`READY`状态将变为`True`，这意味着证书已经配置好，我们可以尝试使用它！

1.  为了尝试由 Let's Encrypt 提供的证书，我们需要将`ngrok`主机名重定向以直接指向 Minikube IP 地址。我们将向`/etc/hosts`文件中添加 HTTP 隧道的主机名，使其解析到 Minikube 实例的 IP 地址。这将导致本地请求发送到 HTTP 隧道的主机名被引导到 Minikube 实例，如下所示图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/e82140ea-df2b-41c7-9abd-a64f465ec373.png)

1.  编辑`/etc/hosts`文件，在我们在本章早些时候添加的行中添加 HTTP 隧道的主机名在`minikube.me`之后。编辑后，该行应类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/bc8718bb-49a9-4a2d-835a-7a07a6b48936.png)

1.  使用`keytool`命令查看 HTTP 隧道主机名暴露的证书：

```java
keytool -printcert -sslserver $NGROK_HOST:443 | grep -E "Owner:|Issuer:"
```

1.  期望收到如下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/02d1d310-1b40-4966-ab53-2a8b2a6dd43a.png)

如果您的`keytool`是本地化的，也就是说，它将其输出打印成除英语外的其他语言，您将需要更改前面`grep`命令使用的`Owner:|Issuer:`字符串，以使用本地化版本。

1.  证书是为 HTTP 隧道的主机名（在前一个示例中为`6cc09528.ngrok.io`）签发的，并由`Fake LE Intermediate X1`使用`Fake LE Root X1`作为其根 CA 签发。这证明 ingress 使用了 Let's Encrypt 的测试证书！

1.  通过使用相同的命令运行`test-em-all.bash`测试脚本总结：

```java
HOST=$NGROK_HOST PORT=443 ./test-em-all.bash
```

期望测试脚本输出通常的结果；检查它以如下结论结束：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/b922e10e-eac0-41a4-8ca6-c714f34b08e5.png)

由 Let's Encrypt 测试环境提供的证书，如前所述，适合开发和测试活动。但由于其根 CA 不被网络浏览器信任，因此它们不能用于生产场景。让我们也尝试使用 Let's Encrypt 的生产环境，该环境能够提供可信的证书，尽管数量有限。

# 使用 Let's Encrypt 的生产环境

为了从 Let's Encrypt 的生产环境获取证书，而不是测试环境，我们必须在 ingress 定义中更改发行者，然后应用更新后的定义。执行以下步骤：

1.  编辑`kubernetes/services/base/ingress-edge-server-ngrok.yml`文件，并更改以下代码：

```java
certmanager.k8s.io/issuer: "letsencrypt-issuer-staging"
```

前面的代码现在应该如下所示：

```java
certmanager.k8s.io/issuer: "letsencrypt-issuer-prod"
```

1.  通过运行以下命令应用更改：

```java
kubectl apply -f kubernetes/services/base/ingress-edge-server-ngrok.yml
```

1.  监控`kubectl get cert --watch`命令的输出，并等待新证书被提供。在应用命令后立即，其就绪状态将更改为`False`，然后过一会儿将回到`True`。这意味着 Cert Manager 已经提供了由 Let's Encrypt 生产环境签发的证书！

1.  使用以下`keytool`命令检查证书：

```java
keytool -printcert -sslserver $NGROK_HOST:443 | grep -E "Owner:|Issuer:"
```

期望输出如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/5d0e1392-a7d9-469e-9b9e-6c49555ebdcb.png)

1.  新证书就像之前为 HTTP 隧道的主机名发行的证书（在前一个示例中为 `6cc09528.ngrok.io`），但这次发行者和根 CA 来自生产环境。这意味着证书应该被网页浏览器信任。

1.  在本地网络浏览器中打开 `https://6cc09528.ngrok.io/actuator/health` URL（将 `6cc09528.ngrok.io` 替换为你的 HTTP 隧道的主机名）。如果你使用 Google Chrome 并点击证书图标（URL 前的锁），你应该会看到如下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/152c06f8-df1e-4c52-b633-84ac22f7717e.png)

如前一个屏幕截图所示，Chrome 报告：此证书有效！

1.  通过以下方式验证 `test-em-all.bash` 测试脚本是否也与此证书一起工作：

```java
HOST=$NGROK_HOST PORT=443 ./test-em-all.bash
```

期望测试脚本输出通常的结果；检查它是否以以下输出结束：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/6d63d35e-1728-4d39-a779-d1f4424d0918.png)

您可以按照相同的过程返回 staging 发行者，同时在 ingress 定义中也将回到 staging 发行者。

# 清理

当你完成后，使用 Docker Compose 运行以下命令清理在 Kubernetes 中（可选在 Docker 中）创建的资源：

1.  使用 *Ctrl + C* 停止 `kubectl get cert --watch` 命令。

1.  使用 *Ctrl* *+* *C.* 停止 HTTP 隧道。

1.  使用以下命令在 Kubernetes 中删除命名空间：

```java
kubectl delete namespace hands-on
```

1.  如果你尝试使用 `./kubernetes/scripts/deploy-prod-env.bash` 脚本部署生产环境，你还需要停止使用 Docker Compose 启动的资源管理器。运行以下命令停止它们：

```java
docker-compose down mongodb mysql rabbitmq
```

既然我们已经自动化了证书的发放，让我们看看如何在没有 Kubernetes 的情况下验证微服务是否工作。让我们看看这是如何完成的。

# 验证在没有 Kubernetes 的情况下微服务是否工作

在本章和上一章中，我们看到了 Kubernetes 平台上的特性，如 config maps、secrets、服务以及 ingress 资源，如何简化开发合作微服务的景观的努力。但重要的是确保微服务的源代码在功能上不依赖于平台。避免此类锁定使得未来如果需要，可以以最小的努力切换到另一个平台。切换平台不应该需要更改源代码，而只需要更改微服务的配置。

使用 Docker Compose 和 `test-em-all.bash` 测试脚本测试微服务，可以确保从功能角度来说它们是工作的，这意味着它们将验证微服务源代码中的功能在没有 Kubernetes 的情况下仍然有效。在没有 Kubernetes 的情况下运行微服务时，我们将失去 Kubernetes 为我们提供的非功能性特性，例如监控、扩展和重启容器。

当使用 Docker Compose 时，我们将映射以下 Kubernetes 特性：

+   而不是使用配置图，我们使用卷，直接从宿主文件系统映射配置文件。

+   而不是使用密钥，我们将敏感信息（如凭据）保存在`.env`文件中。

+   而不是入口，我们将使用 Spring Cloud Gateway。

+   代替服务，我们将将客户端使用的主机名直接映射到容器的主机名，这意味着我们将不实施任何服务发现，并且无法扩展容器。

使用这种方式的 Docker Compose 将在非功能性方面与使用 Kubernetes 相比具有显著劣势。但是，鉴于 Docker Compose 只用于运行功能测试，这是可以接受的。

在我们使用 Docker Compose 运行测试之前，让我们查看一下`docker-compose*.yml`文件中的代码更改。

# Docker Compose 源代码的变化

要在 Kubernetes 之外使用 Docker Compose 运行微服务，对`docker-compose*.yml`文件应用了以下更改：

+   移除了配置服务器定义

+   移除了以下配置服务器环境变量的使用：`CONFIG_SERVER_USR`和`CONFIG_SERVER_PWD`

+   在需要从配置仓库读取配置文件的每个容器中，将`config-repo`文件夹作为卷映射。

+   定义了`SPRING_CONFIG_LOCATION`环境变量，以指向配置仓库中的配置文件。

+   将敏感信息如凭据和密码存储在 Docker Compose 的`.env`文件中的 TLS 证书中

+   使用在`.env`文件中定义的变量，为访问资源管理器的凭据定义环境变量。

例如，在`docker-compose.yml`中，`product`微服务的配置如下所示：

```java
product:
  build: microservices/product-service
  image: hands-on/product-service
  environment:
    - SPRING_PROFILES_ACTIVE=docker
    - SPRING_CONFIG_LOCATION=file:/config-repo/application.yml,file:/config-repo/product.yml
    - SPRING_RABBITMQ_USERNAME=${RABBITMQ_USR}
    - SPRING_RABBITMQ_PASSWORD=${RABBITMQ_PWD}
    - SPRING_DATA_MONGODB_AUTHENTICATION_DATABASE=admin
    - SPRING_DATA_MONGODB_USERNAME=${MONGODB_USR}
    - SPRING_DATA_MONGODB_PASSWORD=${MONGODB_PWD}
  volumes:
    - $PWD/config-repo:/config-repo
```

以下是前述源代码的解释：

+   `config-repo`文件夹作为卷映射到容器的`/config-repo`。

+   `SPRING_CONFIG_LOCATION`环境变量告诉 Spring 在哪里找到属性文件，在本例中，是`/config-repo/application.yml`和`/config-repo/product.yml`文件。

+   根据`.env`文件的内容，设置访问 RabbitMQ 和 MongoDB 的凭据作为环境变量。

前述源代码中提到的凭据在`.env`文件中定义为：

```java
RABBITMQ_USR=rabbit-user-prod
RABBITMQ_PWD=rabbit-pwd-prod
MONGODB_USR=mongodb-user-prod
MONGODB_PWD=mongodb-pwd-prod
```

# 使用 Docker Compose 进行测试

要用 Docker Compose 进行测试，我们将使用 Docker Desktop（以前称为 Docker for macOS）而不是 Minikube。执行以下步骤：

1.  要以 Docker Desktop 而不是 Minikube 运行 Docker 客户端，请运行以下命令：

```java
eval $(minikube docker-env --unset)
```

1.  为了节省内存，您可能想要停止 Minikube 实例：

```java
minikube stop 
```

1.  启动 Docker Desktop（如果尚未运行）。

1.  使用以下命令在 Docker Desktop 中构建 Docker 镜像：

```java
docker-compose build
```

1.  使用 RabbitMQ（每个主题一个分区）运行测试：

```java
COMPOSE_FILE=docker-compose.yml ./test-em-all.bash start stop
```

测试应该从启动所有容器开始，运行测试，最后停止所有容器。预期输出如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/949cd3b9-d551-4336-a25d-a256cae5ad6e.png)

1.  可选地，使用具有多个分区的 RabbitMQ 运行测试：

```java
COMPOSE_FILE=docker-compose-partitions.yml ./test-em-all.bash start stop
```

预期输出应该与前面的测试类似。

1.  或者，使用具有多个分区的 Kafka 运行测试：

```java
COMPOSE_FILE=docker-compose-kafka.yml ./test-em-all.bash start stop
```

预期输出应该与前面的测试类似。

1.  停止 Docker Desktop 以节省内存。

1.  如果之前停止了 Minikube 实例，请启动它，并将默认命名空间设置为`hands-on`：

```java
minikube start
kubectl config set-context $(kubectl config current-context) --namespace=hands-on
```

1.  将 Docker 客户端指向 Minikube 实例中的 Kubernetes 集群：

```java
eval $(minikube docker-env)
```

通过这些测试的成功执行，我们验证了在没有 Kubernetes 的情况下微服务也能正常工作。

# 总结

在本章中，我们看到了 Kubernetes 的功能如何简化微服务架构，这意味着我们需要开发的支撑服务数量减少了，这些服务原本需要和微服务一起部署。我们看到了如何使用 Kubernetes 的配置映射（config maps）和机密（secrets）来替代 Spring Cloud Config Server，以及如何使用 Kubernetes 入口（ingress）来替代基于 Spring Cloud Gateway 的边缘服务。

使用 Cert Manager 和 Let's Encrypt 允许我们自动为 ingress 暴露的 HTTPS 端点提供证书，从而消除了手动且繁琐的工作。由于我们运行在本地 Minikube 实例中的 Kubernetes 集群无法从互联网访问，我们使用了`ngrok`来建立从互联网到 Minikube 实例的 HTTP 隧道。HTTP 隧道被 Let's Encrypt 用来验证我们是否是请求证书的 DNS 名的所有者。

为了验证微服务的源代码可以在其他平台上运行，也就是说不是锁定在 Kubernetes 上，我们使用 Docker Compose 部署了微服务并运行了`test-em-all.bash`测试脚本。

在下一章中，我们将介绍服务网格（service mesh）的概念，并学习如何使用服务网格产品**Istio**来改善部署在 Kubernetes 上的合作微服务景观的可观测性、安全性、弹性和路由。

前往下一章！

# 问题

1.  Spring Cloud Config Server 是如何被 Kubernetes 资源替代的？

1.  Spring Cloud Gateway 是如何被 Kubernetes 资源替代的？

1.  ACME 代表什么，它有什么用途？

1.  Cert Manager 和 Let's Encrypt 在自动化提供证书中扮演什么角色？

1.  在自动化证书提供过程中涉及哪些 Kubernetes 资源？

1.  我们为什么使用`ngrok`，以及如何修改以去除对`ngrok`的使用？

1.  我们为什么使用 Docker Compose 运行测试？


# 第十八章：使用服务网格改善可观测性和管理

在本章中，你将介绍服务网格的概念，并了解其功能如何用于处理微服务系统架构在安全性、策略执行、弹性和流量管理方面的挑战。服务网格还可以用于提供可观测性，即可视化服务网格中微服务之间流量流动的能力。

服务网格在与本书前面所学的 Spring Cloud 和 Kubernetes 的功能有所重叠的同时，也提供了大部分 Spring Cloud 和 Kubernetes 所没有的功能，正如我们将在本章所看到的。

本章将涵盖以下主题：

+   介绍服务网格概念以及 Istio，一个流行的开源实现

+   你还将学习如何进行以下操作：

    +   在 Kubernetes 中部署 Istio

    +   创建一个服务网格

    +   观察服务网格

    +   保护服务网格

    +   确保服务网格具有弹性

    +   使用服务网格执行零停机部署

    +   使用 Docker Compose 测试微服务架构，以确保微服务中的源代码既不受 Kubernetes 或 Istio 的限制。

# 技术要求

本书中描述的所有命令都是在 MacBook Pro 上使用 macOS Mojave 运行的，但修改这些命令以在另一个平台（如 Linux 或 Windows）上运行应该是非常直接的。

本章唯一需要的新工具是 Istio 的命令行工具`istioctl`。这可以通过使用 Homebrew 以下命令进行安装：

```java
brew install istioctl
```

本章的源代码可以在 GitHub 上找到，地址为[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter18`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter18)。

为了能够按照书中所述运行命令，你需要把源代码下载到一个文件夹中，并设置一个环境变量`$BOOK_HOME`，使其指向该文件夹。示例命令包括以下内容：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter18
```

Java 源代码是为 Java 8 编写的，并在 Java 12 上进行了测试。本章使用了 Spring Cloud 2.1, SR2（也被称为**Greenwich**版本），Spring Boot 2.1.6 和 Spring 5.1.8，即在撰写本章时可用的 Spring 组件的最新版本。源代码已经使用 Kubernetes V1.15 进行了测试。

本章中的所有源代码示例均来自`$BOOK_HOME/Chapter18`的源代码，但在许多情况下，为了去除源代码中不相关的内容（如注释、导入和日志语句），对这些示例进行了编辑。

如果你想查看源代码中第十八章，*使用服务网格提高可观测性和管理能力*的更改，也就是使用 Istio 创建服务网格所需的更改，你可以将其与第十七章，*作为替代实现 Kubernetes 特性*的源代码进行比较。你可以使用你喜欢的差异工具，比较这两个文件夹，`$BOOK_HOME/Chapter17`和`$BOOK_HOME/Chapter18`。

# 使用 Istio 的服务网格简介

服务网格是一个基础设施层，用于控制和观察服务之间的通信，例如微服务。服务网格的功能，例如可观测性、安全性、策略执行、弹性和流量管理，是通过控制和监控服务网格内的所有内部通信实现的，即服务网格中微服务之间的通信。服务网格中的一个核心组件是一个轻量级的**代理**组件，它被注入到将成为服务网格一部分的所有微服务中。微服务所有进出流量都被配置为通过其代理组件。代理组件在运行时通过服务网格中的**控制平面**使用代理暴露的 API 进行配置。控制平面还通过这些 API 从代理收集遥测数据，以可视化服务网格中的流量流动。

服务网格还包括一个**数据平面**，由服务网格中所有微服务中的代理组件以及处理来自和服务网格之间外部传入和传出流量的单独组件组成。以下图表说明了这一点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/6f4234c5-40c7-405d-856e-9e11009c242d.png)

第一个公开可用的服务网格实现是开源项目 Linkerd，由 Buoyant 管理([`linkerd.io`](https://linkerd.io))，其起源于 Twitter 的 Finagle 项目([`twitter.github.io/finagle`](http://twitter.github.io/finagle))。它于 2016 年推出，一年后的 2017 年，IBM、Google 和 Lyft 推出了开源项目 Istio([`istio.io`](https://istio.io))。

在 Istio 中，核心组件之一，代理组件，是基于 Lyft 的 Envoy 代理([`www.envoyproxy.io`](https://www.envoyproxy.io))。在撰写本章时，Linkerd 和 Istio 是两个最受欢迎且广泛使用的服务网格实现。在本章中，我们将使用 Istio。

Istio 可以在各种环境中部署，包括 Kubernetes（参见 [`istio.io/docs/setup`](https://istio.io/docs/setup)）。在 Kubernetes 上部署 Istio 时，其运行时组件被部署到一个单独的 Kubernetes 命名空间 `istio-system` 中。Istio 还提供一套 Kubernetes **自定义资源定义**（**CRD**）。CRD 用于在 Kubernetes 中扩展其 API，即添加新的对象到其 API 中。添加的 Istio 对象用于配置 Istio 的使用方式。最后，Istio 提供了一个 CLI 工具 `istioctl`，它将用于将 Istio 代理注入到参与服务网格的微服务中。

如前所述，Istio 被分为控制平面和数据平面。作为一个操作员，我们将通过在 Kubernetes API 服务器中创建 Istio 对象来定义期望的状态，例如，声明路由规则。控制平面将读取这些对象，并向数据平面中的代理发送命令，以根据期望的状态采取行动，例如，配置路由规则。代理处理微服务之间的实际通信，并向控制平面报告遥测数据。遥测数据被控制平面的各个组件用来可视化服务网格中正在发生的事情。

在以下小节中，我们将涵盖以下主题：

+   如何将 Istio 代理注入到微服务中

+   本章我们将使用的 Istio API 对象

+   构成 Istio 控制平面和数据平面的运行时组件

+   引入 Istio 后微服务景观的变化

# 将 Istio 代理注入现有微服务

我们在前几章中在 Kubernetes 中部署的微服务作为一个容器在 Kubernetes pod 中运行（回顾第十五章，*Kubernetes 简介*中的*介绍 Kubernetes API 对象*部分）。要使一个微服务加入基于 Istio 的服务网格，向每个微服务中注入 Istio 代理。这是通过向运行 Istio 代理的 pod 添加一个额外容器来实现的。

被添加到 pod 中以支持主容器（如 Istio 代理）的容器被称为*sidecar*。

以下图表显示了如何将 Istio 代理作为*sidecar*注入到样本 pod **Pod A** 中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a824d18b-8f01-4c08-97ef-d697d7154fc8.png)

在 pod 中的主容器**容器 A**，被配置通过 Istio 代理路由其所有流量。

Istio 代理可以当创建部署对象时自动注入，也可以使用`istioctl`工具手动注入。

在本章中，我们将手动注入 Istio 代理。原因是 Istio 代理不支持 MySQL、MongoDB 和 RabbitMQ 使用的协议，所以我们只会在使用 HTTP 协议的 pod 中注入 Istio 代理。可以通过以下命令将 Istio 代理注入现有部署对象的 pods：

```java
kubectl get deployment sample-deployment -o yaml | istioctl kube-inject -f - | kubectl apply -f -
```

这个命令初看起来可能有些令人畏惧，但实际上它只是三个独立的命令。前一个命令将其输出通过管道发送给下一个命令，即`|`字符。让我们逐一介绍每个命令：

1.  `kubectl get deployment`命令从 Kubernetes API 服务器获取名为`sample-deployment`的部署的当前定义，并以 YAML 格式返回其定义。

1.  `istioctl kube-inject`命令从`kubectl get deployment`命令中读取定义，并在部署处理的 pod 中添加一个额外的 Istio 代理容器。部署对象中现有容器的配置更新，以便传入和传出的流量都通过 Istio 代理。

    `istioctl`命令返回部署对象的新定义，包括一个 Istio 代理的容器。

1.  `kubectl apply`命令从`istioctl kube-inject`命令中读取更新后的配置，并应用更新后的配置。将启动与之前我们所见过的相同的滚动升级（请参阅第十六章，*将我们的微服务部署到 Kubernetes*中的*执行滚动升级*部分），部署的 pods 将以相同的方式开始。

`kubernetes/scripts`文件夹中的部署脚本已扩展为使用`istioctl`来注入 Istio 代理。有关详细信息，请参考即将到来的*创建服务网格*部分。

# 介绍 Istio API 对象

Istio 通过其 CRDs 使用许多对象扩展了 Kubernetes API。回顾 Kubernetes API，请参考第十五章，*Kubernetes 简介*中的*介绍 Kubernetes API 对象*部分。在本章中，我们将使用以下 Istio 对象：

+   `Gateway`用于配置如何处理服务网格的入站和出站流量。网关依赖于一个虚拟服务，将入站流量路由到 Kubernetes 服务。我们将使用网关对象接受通过 HTTPS 到 DNS 名称`minikube.me`的入站流量。有关详细信息，请参考*用 Istio Ingress Gateway 替换 Kubernetes Ingress 资源作为边缘服务器*部分。

+   `VirtualService`用于在服务网格中定义路由规则。我们将使用虚拟服务来描述如何将来自 Istio 网关的流量路由到 Kubernetes 服务和服务之间。我们还将使用虚拟服务注入故障和延迟，以测试服务网格的可靠性和弹性能力。

+   `DestinationRule`用于定义路由到特定服务（即目的地）的流量的策略和规则（使用虚拟服务）。我们将使用目的地规则来设置加密策略，以加密内部 HTTP 流量并定义描述服务可用版本的服务子集。在将微服务的现有版本部署到新版本时，我们将使用服务子集执行零停机（蓝/绿）部署。

+   `Policy`用于定义请求如何进行认证。我们将使用策略要求服务网格传入的请求使用基于 JWT 的 OAuth 2.0/OIDC 访问令牌进行认证。请参阅本章节中*使用 OAuth 2.0/OIDC 访问令牌认证外部请求*部分。策略还可以用于定义服务网格内部通信的安全部分。例如，策略可以要求内部请求使用 HTTPS 进行加密或允许明文请求。最后，可以使用`MeshPolicy`对象定义适用于整个服务网格的全球策略。

# 在 Istio 中引入运行时组件

Istio 包含许多运行时组件，在选择使用哪些组件方面具有高度可配置性，并提供了对每个组件配置的细粒度控制。有关我们将在此章节中使用的配置信息，请参阅本章节中*在 Kubernetes 集群中部署 Istio*部分。

在本章节使用的配置中，Istio 控制平面包含以下运行时组件：

+   **Pilot**：负责向所有边车提供服务网格配置的更新。

+   **Mixer**：包含两个不同的运行时组件：

    +   **策略**–执行网络策略，例如认证、授权、速率限制和配额。

    +   **遥测**–收集遥测信息并将其发送到 Prometheus，例如。

+   **Galley**：负责收集和验证配置信息，并将其分发到控制平面上的其他 Istio 组件。

+   **Citadel**：负责发放和轮换内部使用的证书。

+   **Kiali**：为服务网格提供可观测性，可视化网格中正在发生的事情。Kiali 是一个独立的开源项目（参见[`www.kiali.io`](https://www.kiali.io)）。

+   **Prometheus**：对基于时间序列的数据执行数据摄取和存储，例如，性能指标。

    Prometheus 是一个独立的开源项目（请参阅[`prometheus.io`](https://prometheus.io)）。

+   **Grafana**：可视化 Prometheus 收集的性能指标和其他时间序列相关数据。Grafana 是一个独立的开源项目（参见[`grafana.com`](https://grafana.com)）。

+   **追踪**：处理并可视化分布式追踪信息。基于 Jaeger，它是一个开源的分布式追踪项目（参考[`www.jaegertracing.io`](https://www.jaegertracing.io)）。Jaeger 提供与 Zipkin 相同的功能，我们在第十四章中使用过，*理解分布式追踪*。

Kiali 通过网页浏览器访问，并集成了 Grafana 以查看性能指标和 Jaeger 以可视化分布式追踪信息。

Istio 数据平面包括以下运行时组件：

+   **入口网关**：处理服务网格的入站流量

+   **出口网关**：处理服务网格的出站流量

+   所有带有 Istio 代理的 pod 都作为边车注入。

Istio 控制平面和数据平面的运行时组件总结如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/bc1d5d4f-c2d3-4504-8d01-506c8fec94c4.png)

在下一节中，我们将介绍由于引入 Istio 而对微服务景观所做的更改。

# 微服务景观的变化

如前所述，Istio 带有与当前在微服务景观中使用的组件在功能上重叠的组件：

+   Istio Ingress Gateway 可以作为边缘服务器，是 Kubernetes Ingress 资源的替代品。

+   Istio 自带的 Jaeger 组件可以用于分布式追踪，而不是 Zipkin。

在接下来的两个子节中，我们将学习为什么以及如何用 Istio Ingress Gateway 替换 Kubernetes Ingress 资源，以及为什么用 Jaeger 替换 Zipkin。

# 用 Istio Ingress Gateway 作为边缘服务器替换 Kubernetes Ingress 资源

在上一章中，我们介绍了 Kubernetes Ingress 资源作为边缘服务器（参考第十七章中的*用 Kubernetes 特性作为替代*部分，*Replacing the Spring Cloud Gateway*）。不幸的是，ingress 资源无法配置以处理 Istio 带来的细粒度路由规则。相反，Istio 有自己的边缘服务器，即 Istio ingress Gateway，在前面的*介绍 Istio 运行时组件*一节中已经介绍过。通过创建前面介绍的*引入 Istio API 对象*一节中描述的 `Gateway` 和 `VisualService` 资源来使用 Istio Ingress Gateway。

因此，以下 Kubernetes Ingress 资源定义文件`kubernetes/services/base/ingress-edge-server.yml`和`kubernetes/services/base/ingress-edge-server-ngrok.yml`已被移除。在*创建服务网格*一节中将添加 Istio `Gateway` 和 `VirtualService` 资源的定义文件。

访问 Istio Ingress Gateway 时使用的 IP 地址与访问 Kubernetes Ingress 资源的 IP 地址不同，因此我们还需要更新映射到主机名`minikube.me`的 IP 地址，我们在运行测试时使用这个主机名。这在本书的*设置对 Istio 服务的访问*一节中处理。

# 简化系统架构，用 Jaeger 替换 Zipkin

在*在 Istio 中引入运行时组件*一节中提到，Istio 内置了对分布式追踪的支持，使用 Jaeger*.*通过 Jaeger，我们可以卸载并简化微服务架构，删除我们在第十四章，*理解分布式追踪*中引入的 Zipkin 服务器。

以下是对源代码所做的更改，以移除 Zipkin 服务器：

+   在所有微服务构建文件`build.gradle`中，已移除了对`org.springframework.cloud:spring-cloud-starter-zipkin`的依赖。

+   在三个 Docker Compose 文件`docker-compose.yml`、`docker-compose-partitions.yml`和`docker-compose-kafka.yml`中，已移除了对 Zipkin 服务器的定义。

+   已删除以下 Zipkin 的 Kubernetes 定义文件：

    +   `kubernetes/services/base/zipkin-server.yml`

    +   `kubernetes/services/overlays/prod/zipkin-server-prod.yml`

在*创建服务网格*一节中，将安装 Jaeger。

由于引入了 Istio，对微服务架构进行了更改。现在我们准备在 Kubernetes 集群中部署 Istio。

# 在 Kubernetes 集群中部署 Istio

在本节中，我们将学习如何在 Kubernetes 集群中部署 Istio 以及如何访问其中的 Istio 服务。

我们将使用在本章撰写时可用的最新版本的 Istio，即 v1.2.4。

我们将使用一个适合在开发环境中测试 Istio 的 Istio 演示配置，即大多数功能启用但配置为最小化资源使用的配置。

此配置不适合生产使用和性能测试。

有关其他安装选项，请参阅[`istio.io/docs/setup/kubernetes/install`](https://istio.io/docs/setup/kubernetes/install)。

要部署 Istio，请执行以下步骤：

1.  按照以下方式下载 Istio：

```java
cd $BOOK_HOME/Chapter18
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=1.2.4 sh -
```

1.  确保您的 Minikube 实例正在运行以下命令：

```java
minikube status
```

如果运行正常，预期会收到类似以下内容的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/b73dc4d8-a721-40eb-87be-a3395fc8c84f.png)

1.  在 Kubernetes 中安装 Istio 特定的自定义资源定义（CRDs）：

```java
for i in istio-1.2.4/install/kubernetes/helm/istio-init/files/crd*yaml; do kubectl apply -f $i; done
```

1.  按照以下方式在 Kubernetes 中安装 Istio 演示配置：

```java
kubectl apply -f istio-1.2.4/install/kubernetes/istio-demo.yaml
```

1.  等待 Istio 部署变得可用：

```java
kubectl -n istio-system wait --timeout=600s --for=condition=available deployment --all
```

命令将会逐一报告 Istio 中的部署资源为可用。在命令结束前，预期会收到 12 条类似于`deployment.extensions/NNN condition met`的消息。这可能会花费几分钟（或更长时间），具体取决于您的硬件和互联网连接速度。

1.  使用以下命令更新 Kiali 的配置文件，为其添加 Jaeger 和 Grafana 的 URL：

```java
kubectl -n istio-system apply -f kubernetes/istio/setup/kiali-configmap.yml && \
kubectl -n istio-system delete pod -l app=kiali && \
kubectl -n istio-system wait --timeout=60s --for=condition=ready pod -l app=kiali
```

配置文件`kubernetes/istio/setup/kiali-configmap.yml`包含了利用下一节中使用的`minikube tunnel`命令设置的 DNS 名称的 Jaeger 和 Grafana 的 URL。

Istio 现在已部署在 Kubernetes 中，但在我们继续创建服务网格之前，我们需要了解一些关于如何在 Minikube 环境中访问 Istio 服务的内容。

# 设置对 Istio 服务的访问

前一小节中用于安装 Istio 的演示配置包含一些与连通性相关的问题需要我们解决。Istio Ingress Gateway 被配置为一个负载均衡的 Kubernetes 服务；也就是说，它的类型是`LoadBalancer`。

它也可以通过 Minikube 实例的 IP 地址上的节点端口访问，端口范围在`30000`-`32767`之间。不幸的是，Istio 中的基于 HTTPS 的路由不能包括端口号；也就是说，Istio 的 Ingress Gateway 必须通过 HTTPS 的默认端口（`443`）访问。因此，不能使用节点端口。相反，必须使用负载均衡器才能使用 Istio 的路由规则进行 HTTPS 访问。

Minikube 包含一个可以用来模拟本地负载均衡器的命令，即`minikube tunnel`。此命令为每个负载均衡的 Kubernetes 服务分配一个外部 IP 地址，包括 Istio Ingress Gateway。这将为我们更新主机名`minikube.me`的翻译提供所需的内容，我们在测试中使用该主机名。现在，主机名`minikube.me`需要被翻译为 Istio Ingress Gateway 的外部 IP 地址，而不是我们在前几章中使用的 Minikube 实例的 IP 地址。

`minikube tunnel`命令还使使用它们的 DNS 名称的集群本地 Kubernetes 服务可用。DNS 名称基于命名约定：`{service-name}.{namespace}.svc.cluster.local`。例如，当隧道运行时，可以从本地网页浏览器通过 DNS 名称`kiali.istio-system.svc.cluster.local`访问 Istio 的 Kiali 服务。

以下图表总结了如何访问 Istio 服务：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/6df8153e-3139-4cc7-9cb2-0f832f9e5129.png)

执行以下步骤来设置 Minikube 隧道：

1.  使 Kubernetes 服务在本地可用。在一个单独的终端窗口中运行以下命令（当隧道运行时，该命令会锁定终端窗口）：

```java
minikube tunnel
```

请注意，此命令要求您的用户具有`sudo`权限，并且在启动和关闭时输入您的密码。在命令要求输入密码之前，会有一两秒钟的延迟，所以很容易错过！

1.  配置`minikube.me`以解析到 Istio Ingress Gateway 的 IP 地址如下：

    1.  获取`minikube tunnel`命令为 Istio Ingress Gateway 暴露的 IP 地址，并将其保存为名为`INGRESS_HOST`的环境变量：

```java
INGRESS_HOST=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

+   1.  更新`/etc/hosts`，使`minikube.me`指向 Istio Ingress Gateway：

```java
echo "$INGRESS_HOST minikube.me" | sudo tee -a /etc/hosts
```

+   1.  删除`/etc/hosts`文件中指向 Minikube 实例（`minikube ip`）IP 地址的`minikube.me`那一行。确认`/etc/hosts`只包含将`minikube.me`翻译为 IP 地址的一条线，并且它指向 Istio Ingress Gateway 的 IP 地址；例如，`$INGRESS_HOST`的值：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/466a71aa-3959-4801-8017-ce9c50266daf.png)

1.  确认 Kiali，Jaeger 和 Grafana 可以通过隧道访问，使用以下命令：

```java
curl -o /dev/null -s -L -w "%{http_code}" http://kiali.istio-system.svc.cluster.local:20001/kiali/
curl -o /dev/null -s -L -w "%{http_code}" http://grafana.istio-system.svc.cluster.local:3000
curl -o /dev/null -s -L -w "%{http_code}" http://jaeger-query.istio-system.svc.cluster.local:16686
```

每个命令应返回`200`（OK）。

`minikube tunnel`命令可能会因为例如您的计算机或虚拟机中的 Minikube 实例被暂停或重新启动而停止运行。在这些情况下，需要手动重新启动该命令。因此，如果您无法调用`https://minikube.me` URL 上的 API，或者 Kiali 的 Web UI 无法访问 Jaeger 以可视化分布式跟踪，或者无法通过 Grafana 以可视化性能指标，总是要检查 Minikube 隧道是否正在运行，并在需要时重新启动它。

# 使用`minikube tunnel`命令的额外好处

运行`minikube tunnel`命令还使可以访问一些其他可能感兴趣的集群内部 Kubernetes 服务成为可能。一旦按照*运行创建服务网格的命令*部分描述的方式启动环境，以下是可以实现的：

+   `product-composite`微服务的`health`端点可以通过以下命令进行检查：

```java
curl -k http://product-composite.hands-on.svc.cluster.local:4004/actuator/health
```

有关端口`4004`的用法的解释，请参阅*观察服务网格*部分。

+   可以在以下命令中访问审查数据库中的 MySQL 表：

```java
mysql -umysql-user-dev -pmysql-pwd-dev review-db -e "select * from reviews" -h mysql.hands-on.svc.cluster.local
```

+   可以通过以下命令访问`product`和`recommendations`数据库中的 MongoDB 集合：

```java
mongo --host mongodb.hands-on.svc.cluster.local -u mongodb-user-dev -p mongodb-pwd-dev --authenticationDatabase admin product-db --eval "db.products.find()"

mongo --host mongodb.hands-on.svc.cluster.local -u mongodb-user-dev -p mongodb-pwd-dev --authenticationDatabase admin recommendation-db --eval "db.recommendations.find()"
```

+   可以通过以下 URL 访问 RabbitMQ 的 Web UI：`http://rabbitmq.hands-on.svc.cluster.local:15672`。使用`rabbit-user-dev`和`rabbit-pwd-dev`凭据登录。

在 Minikube 隧道就位后，我们现在准备创建服务网格。

# 创建服务网格

在 Istio 部署完成后，我们准备创建服务网格。我们将使用`kubernetes/scripts/deploy-dev-env.bash`脚本来为开发和测试设置环境。

创建服务网格所需的步骤基本上与我们在第十七章中使用的*作为替代实现 Kubernetes 特性*（请参阅*使用 Kubernetes ConfigMaps, secrets 和 ingress 进行测试*部分）相同。首先让我们看看已经对 Kubernetes 定义文件做了哪些添加，以设置服务网格，然后再运行创建服务网格的命令。

# 源代码更改

为了能够在由 Istio 管理的服务网格中运行微服务，已经对 Kubernetes 定义文件进行了以下更改：

+   部署脚本已更新以注入 Istio 代理

+   Kubernetes 定义文件的文件结构已更改

+   已经添加了 Istio 的 Kubernetes 定义文件

让我们逐一进行。

# 更新部署脚本以注入 Istio 代理

在`kubernetes/scripts`文件夹中的用于在 Kubernetes 中部署微服务的脚本`deploy-dev-env.bash`和`deploy-prod-env.bash`，都已更新以向五个微服务注入 Istio 代理，即`auth-server`、`product-composite`、`product`、`recommendation`和`review`服务。

`deploy-prod-env.bash`脚本将在*执行零停机部署*部分使用。

之前在*向现有微服务中注入 Istio 代理*部分描述的`istioctl kube-inject`命令已添加到两个部署脚本中，如下所示：

```java
kubectl get deployment auth-server product product-composite recommendation review -o yaml | istioctl kube-inject -f - | kubectl apply -f -
```

由于`kubectl apply`命令将启动滚动升级，以下命令已添加以等待升级完成：

```java
waitForPods 5 'version=<version>'
```

在滚动升级期间，我们将为每个微服务运行两个容器：一个没有 Istio 代理的老版本容器和一个注入了 Istio 代理的新版本容器。`waitForPods`函数将等待直到老版本容器终止；也就是说，滚动升级完成，只有五个新容器在运行。为了确定要等待哪个容器，使用了一个名为`version`的标签。在开发环境中，所有微服务容器都标记为`version=latest`。

例如，产品微服务的部署文件`kubernetes/services/base/deployments/product-deployment.yml`，`version`标签的定义如下：

```java
metadata:
  labels:
    version: latest
```

在第*执行零停机部署*部分，我们将从版本`v1`升级微服务到`v2`，版本标签将设置为`v1`和`v2`。

最后，脚本中已添加以下命令，以使脚本等待部署及其容器就绪：

```java
kubectl wait --timeout=120s --for=condition=Ready pod --all
```

在查看部署脚本的更新后，让我们看看引入 Istio 后 Kubernetes 定义文件的文件结构有何变化。

# 更改 Kubernetes 定义文件的文件结构

自第十六章《将我们的微服务部署到 Kubernetes》以来，`kubernetes/services`中的 Kubernetes 定义文件结构已经有所扩展，*Introduction to Kustomize*部分进行了说明，现在的结构如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/cc35c1d8-4834-4161-9759-347150bb845d.png)

`base`文件夹包含三个子文件夹。这是因为在*执行零停机部署*部分，我们将同时运行微服务的两个版本，即每个微服务版本一个容器。由于容器由部署对象管理，我们还需要每个微服务两个部署对象。为了实现这一点，部署对象的基础版本已放在一个单独的文件夹`deployments`中，服务对象和 Istio 定义分别放在它们自己的基础文件夹：`services`和`istio`。

在开发环境中，我们将为每个微服务运行一个版本。其 kustomization 文件`kubernetes/services/overlays/dev/kustomization.yml`已更新，以将所有三个文件夹作为基本文件夹包括在内：

```java
bases:
- ../../base/deployments
- ../../base/services
- ../../base/istio
```

有关如何在生产环境设置中部署两个并发微服务版本的详细信息，请参阅后面的*零停机部署*部分。

现在，让我们也浏览一下 Istio 文件夹中的新文件。

# 为 Istio 添加 Kubernetes 定义文件

在`istio`文件夹中添加了 Istio 定义。本节中感兴趣的 Istio 文件是网关定义及其相应的虚拟服务。其他 Istio 文件将在*使用 OAuth 2.0/OIDC 访问令牌进行外部请求认证*和*使用相互认证（mTLS）保护内部通信*部分进行解释。

Istio 网关在`kubernetes/services/base/istio/gateway.yml`文件中声明，如下所示：

```java
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: hands-on-gw
spec:
  selector:
    istio: ingressgateway
  servers:
  - hosts:
    - "minikube.me"
    port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      serverCertificate: /etc/istio/ingressgateway-certs/tls.crt
      privateKey: /etc/istio/ingressgateway-certs/tls.key
```

以下是对前面源代码的一些解释：

+   网关名为`hands-on-gw`；这个名称被下面的虚拟服务使用。

+   `selector`字段指定网关资源将由内置的 Istio Ingress Gateway 处理。

+   `hosts`和`port`字段指定网关将使用端口`443`上的 HTTPS 处理`minikube.me`主机名的传入请求。

+   `tls`字段指定了 Istio Ingress Gateway 用于 HTTPS 通信的证书和私钥的位置。有关这些证书文件如何创建的详细信息，请参阅*使用 HTTPS 和证书保护外部端点*部分。

用于将网关请求路由到`product-composite`服务的虚拟服务对象，即`kubernetes/services/base/istio/product-composite-virtual-service.yml`，如下所示：

```java
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: product-composite-vs
spec:
  hosts:
  - "minikube.me"
  gateways:
  - hands-on-gw
  http:
  - match:
    - uri:
        prefix: /product-composite
    route:
    - destination:
        port:
          number: 80
        host: product-composite
```

前面源代码的解释如下：

+   `hosts`字段指定虚拟服务将路由发送到主机`minikube.me`的请求。

+   `match`和`route`块指定包含以`/product-composite`开头的 URI 的请求将被转发到名为`product-composite`的 Kubernetes 服务。

在前面的源代码中，目标主机使用其简称指定，也就是说，`product-composite`。由于本章节的示例将所有 Kubernetes 定义保存在同一个命名空间`hands-on`中，因此这样可以工作。如果不是这种情况，Istio 文档建议使用主机的**完全限定域名**（**FQDN**）代替，即`product-composite.hands-on.svc.cluster.local`。

最后，虚拟服务对象用于将网关请求路由到认证服务器，即`kubernetes/services/base/istio/auth-server-virtual-service.yml`，看起来非常相似，不同之处在于它将带有`/oauth`前缀的请求路由到 Kubernetes 服务`auth-server`。

在源代码中实施了这些更改后，我们现在准备创建服务网格。

# 运行创建服务网格的命令

通过运行以下命令创建服务网格：

1.  使用以下命令从源代码构建 Docker 镜像：

```java
cd $BOOK_HOME/Chapter18
eval $(minikube docker-env)
./gradlew build && docker-compose build
```

1.  重新创建`hands-on`命名空间，并将其设置为默认命名空间：

```java
kubectl delete namespace hands-on
kubectl create namespace hands-on
kubectl config set-context $(kubectl config current-context) --namespace=hands-on 
```

1.  通过运行以下命令执行部署：

```java
./kubernetes/scripts/deploy-dev-env.bash 
```

1.  部署完成后，验证我们每个微服务 pods 中都有两个容器：

```java
kubectl get pods
```

期望的响应类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/f0040d84-3544-45f4-9dd2-fd7a30e5ea31.png)

注意，运行我们微服务的 pods 每个 pods 报告两个容器；也就是说，它们有一个作为边车的 Istio 代理被注入！

1.  使用以下命令运行常规测试：

```java
./test-em-all.bash
```

`script test-em-all.bash`的默认值已从之前的章节更新，以适应在 Minikube 中运行的 Kubernetes。

期望输出与我们在前面的章节中看到的内容类似：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/f18d0079-84bb-4a36-96db-00e71ec593df.png)

1.  你可以通过运行以下命令手动尝试 API。

```java
ACCESS_TOKEN=$(curl -k https://writer:secret@minikube.me/oauth/token -d grant_type=password -d username=magnus -d password=password -s | jq .access_token -r)

curl -ks https://minikube.me/product-composite/2 -H "Authorization: Bearer $ACCESS_TOKEN" | jq .productId
```

期望在响应中收到请求的产品 ID，`2`。

服务网格运行起来后，让我们看看如何使用 Kiali 观察服务网格中正在发生的事情！

# 观察服务网格

在本节中，我们将使用 Kiali 和 Jaeger 一起观察服务网格中的情况。有关使用 Grafana 进行性能监控的信息，请参阅第二十章，*监控微服务*。

在这样做之前，我们需要消除由 Kubernetes 的生存和就绪探针执行的健康检查产生的某些噪声。在前面的章节中，它们一直使用与 API 请求相同的端口。这意味着 Istio 将收集健康检查和发送到 API 的请求的遥测数据。这会导致 Kiali 显示的图表不必要地变得混乱。Kiali 可以过滤掉我们不感兴趣的流量，但一个更简单的解决方案是使用不同的端口进行健康检查。

微服务可以配置为使用单独的端口来发送到 actuator 端点的请求，例如，发送到`/actuator/health`端点的健康检查。所有微服务的共同配置文件`config-repo/application.yml`中已添加以下行：

```java
management.server.port: 4004
```

这将使所有微服务使用端口`4004`来暴露健康端点。`kubernetes/services/base/deployments`文件夹中的所有部署文件都已被更新为在其生存和就绪探针中使用端口`4004`。

Spring Cloud Gateway（保留此内容，这样我们可以在 Docker Compose 中运行测试）将继续为 API 和`health`端点的请求使用相同的端口。在`config-repo/gateway.yml`配置文件中，管理端口已恢复为用于 API 的端口：

```java
management.server.port: 8443
```

处理了发送到健康端点的请求后，我们可以开始通过服务网格发送一些请求。

我们将使用`siege`开始一次低流量的负载测试，我们在第十六章中了解过，*将我们的微服务部署到 Kubernetes*（参考*执行滚动升级*部分）。之后，我们将浏览 Kiali 的一些最重要的部分，了解如何使用 Kiali 观察服务网格。我们还将探索 Kiali 与 Jaeger 的集成以及 Jaeger 如何用于分布式跟踪：

使用以下命令开始测试：

```java
ACCESS_TOKEN=$(curl -k https://writer:secret@minikube.me/oauth/token -d grant_type=password -d username=magnus -d password=password -s | jq .access_token -r)

siege https://minikube.me/product-composite/2 -H "Authorization: Bearer $ACCESS_TOKEN" -c1 -d1
```

第一个命令将获取一个 OAuth 2.0/OIDC 访问令牌，该令牌将在下一个命令中使用，其中`siege`用于向 product-composite API 每秒提交一个 HTTP 请求。

预计`siege`命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/124bc0e4-2fda-4b01-be2f-81c0653eaa0a.png)

1.  使用`http://kiali.istio-system.svc.cluster.local:20001/kiali` URL 在 Web 浏览器中打开 Kiali 的 Web UI，并使用以下用户名和密码登录：`admin`和`admin`。预计会出现如下网页：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/621bc3a8-d0ad-4254-9de3-fea188d12428.png)

1.  点击概述标签，如果尚未激活。

1.  在 hands-on 命名空间中点击图表图标。预计会显示一个图表，代表服务网格当前的流量流向，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/8e6dcb80-2f70-4714-acb9-b8abcf8e49cd.png)

1.  点击显示按钮，取消选择服务节点，选择流量动画。

    Kiali 显示一个代表通过服务网格发送的当前请求的图表，其中活动请求由小移动圆圈和箭头表示。

    这为服务网格中正在发生的事情提供了相当不错的初始概览！

1.  现在让我们使用 Jaeger 进行一些分布式跟踪：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/36f57f31-b217-474d-8bd6-99ddb55b7370.png)

1.  点击产品节点。

1.  点击服务：product 链接。在服务网页上，点击菜单中的跟踪标签，Kiali 将使用 Jaeger 显示产品服务参与的跟踪的内嵌视图。预计会出现如下网页：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/4e530bf8-fba4-4321-9f45-450dfb3fe9dc.png)

1.  点击其中一个跟踪项进行检查。预计会出现如下网页：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/402e5bb3-c03c-48dc-a5aa-ed14e971ecb0.png)

这基本上与 Zipkin 相同跟踪信息，在第十四章中提供，*理解分布式跟踪*。

还有很多值得探索的内容，但这已经足够作为一个介绍了。可以自由地探索 Kiali、Jaeger 和 Grafana 的 Web UI。

在第二十章中，*监控微服务*，我们将进一步探索性能监控功能。

让我们继续学习如何使用 Istio 改进服务网格的安全性！

# 保护服务网格

在本节中，我们将学习如何使用 Istio 提高服务网格的安全性。我们将涵盖以下主题：

+   如何使用 HTTPS 和证书保护外部端点

+   如何要求外部请求使用 OAuth 2.0/OIDC 访问令牌进行认证

+   如何使用相互认证（mTLS）保护内部通信

让我们现在理解这些每个部分。

# 使用 HTTPS 和证书保护外部端点

在*创建服务网格*一节中，我们看到了 Istio Ingress Gateway 是如何配置使用以下证书文件来保护通过 HTTPS 发送到`minikube.me`的外部请求的。Istio Ingress Gateway 的配置如下：

```java
spec:
  servers:
  - hosts:
    - "minikube.me"
    ...
    tls:
      mode: SIMPLE
      serverCertificate: /etc/istio/ingressgateway-certs/tls.crt
      privateKey: /etc/istio/ingressgateway-certs/tls.key 
```

但这些文件是从哪里来的，你可能会问？

我们可以通过运行以下命令来查看 Istio Ingress Gateway 的配置：

```java
kubectl -n istio-system get deploy istio-ingressgateway -o json
```

我们会发现它准备挂载一个名为`istio-ingressgateway-certs`的可选证书，并将其映射到`/etc/istio/ingressgateway-certs/`文件夹：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/206f48a3-7bfa-42df-97ad-e1be388adda9.png)

这导致从名为`istio-ingressgateway-certs`的秘密中创建了证书文件`tls.crt`和`tls.key`，使 Istio Ingress Gateway 能够在`/etc/istio/ingressgateway-certs/tls.crt`和`/etc/istio/ingressgateway-certs/tls.key`文件路径上使用。

这个秘密的创建是通过在`kubernetes/scripts`文件夹中使用`deploy-dev-env.bash`和`deploy-prod-env.bash`部署脚本来处理的，使用以下命令：

```java
kubectl create -n istio-system secret tls istio-ingressgateway-certs \
--key kubernetes/cert/tls.key --cert kubernetes/cert/tls.crt
```

证书文件是在第十七章实现 Kubernetes 特性作为替代中创建的，*使用 Kubernetes ConfigMaps、secrets 和 ingress 进行测试*部分。

为了验证确实是这些证书被 Istio Ingress Gateway 使用，我们可以运行以下命令：

```java
keytool -printcert -sslserver minikube.me:443 | grep -E "Owner:|Issuer:"
```

期待以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a5d99e95-d5ab-49fc-b2c3-62afb06295d1.png)

输出显示证书是为`minikube.se`发行的，并且是自签名的，即发行者也是`minikube.me`。

这个自签名的证书可以替换为信任的证书授权机构（CA）为生产使用案例购买的证书。Istio 最近添加了对使用例如 cert manager 和 Let's Encrypt 的信任证书的自动化支持，正如我们在第十七章实现 Kubernetes 特性作为替代中一样，*使用 cert manager 和 Let's Encrypt 提供证书*部分。这种支持目前过于复杂，不适合这一章。

证书配置验证完成后，让我们接下来看看 Istio Ingress Gateway 如何保护微服务免受未经认证的请求**。

# 使用 OAuth 2.0/OIDC 访问令牌验证外部请求

Istio Ingress Gateway 能够要求并验证基于 JWT 的 OAuth 2.0/OIDC 访问令牌，换句话说，保护服务网格中的微服务免受外部未认证请求的侵害。回顾 JWT，OAuth 2.0 和 OIDC，请参阅第十一章《保护 API 的访问》，*安全的 API 访问*（参考*使用 OAuth 2.0 和 OpenID Connect 对 API 访问进行身份验证和授权*部分）。

为了启用身份验证，我们需要创建一个 Istio `Policy`对象，指定应受保护的目标和应信任的访问令牌发行商，即 OAuth 2.0/OIDC 提供程序。这是在`kubernetes/services/base/istio/jwt-authentication-policy.yml`文件中完成的，并如下所示：

```java
apiVersion: "authentication.istio.io/v1alpha1"
kind: "Policy"
metadata:
  name: "jwt-authentication-policy"
spec:
  targets:
  - name: product-composite
  peers:
  - mtls:
      mode: PERMISSIVE
  origins:
  - jwt:
      issuer: "http://auth-server.local"
      jwksUri: "http://auth-server.hands-on.svc.cluster.local/.well-known/jwks.json"
  principalBinding: USE_ORIGIN
```

以下源代码的解释如下：

+   `targets`列表指定了将对发送到`product-composite`微服务的请求执行身份验证检查。

+   `origins`列表指定了我们依赖的 OAuth 2.0/OIDC 提供程序。对于每个发行者，指定了发行者的名称及其 JSON Web 密钥集的 URL。回顾一下，请参阅第十一章《保护 API 的访问》，*介绍 OpenId Connect*（参考*使用 OAuth 2.0 和 OpenID Connect 对 API 访问进行身份验证和授权*部分）。我们已经指定了本地认证服务器，`http://auth-server.local`。

策略文件是由`kubernetes/scripts/deploy-dev-env.bash`部署脚本在*运行创建服务网格的命令*部分应用的。

要验证无效请求是否被 Istio Ingress Gateway 拒绝而不是`product-composite`微服务，最简单的方法是发送一个没有访问令牌的请求，并观察返回的错误信息。在认证失败的情况下，Istio Ingress Gateway 会返回以下错误信息，`Origin authentication failed.`，而`product-composite`微服务会返回一个空字符串。两者都返回 HTTP 代码`401`（未授权）。

使用以下命令尝试：

1.  发送类似以下内容的无访问令牌请求：

```java
curl https://minikube.me/product-composite/2 -kw " HTTP Code: %{http_code}\n"
```

期待一个说`Origin authentication failed. HTTP Code: 401`的响应。

1.  暂时使用以下命令删除策略：

```java
kubectl delete -f kubernetes/services/base/istio/jwt-authentication-policy.yml
```

等待一分钟，让策略更改传播到 Istio Ingress Gateway，然后尝试不带访问令牌发送请求。现在响应应仅包含 HTTP 代码：`HTTP Code: 401`。

1.  使用以下命令再次启用策略：

```java
kubectl apply -f kubernetes/services/base/istio/jwt-authentication-policy.yml
```

**建议的额外练习：**尝试使用 Auth0 OIDC 提供程序，如第十一章《保护 API 的访问》所述，*使用 OpenID Connect 提供程序 Auth0 进行测试*。将您的 Auth0 提供程序添加到`jwt-authentication-policy.yml`中。在我的情况下，它如下所示：

```java
  - jwt:
      issuer: "https://dev-magnus.eu.auth0.com/" 
      jwksUri: "https://dev-magnus.eu.auth0.com/.well-known/jwks.json"
```

现在，让我们转向我们将要在 Istio 中涵盖的最后一种安全机制——使用相互认证（mTLS）保护服务网格内部通信的自动保护。

# 使用相互认证（mTLS）保护内部通信

在本节中，我们将学习如何配置 Istio 以自动保护服务网格内部通信，使用*相互* *认证*，即 mTLS。在使用相互认证时，服务端通过暴露证书来证明其身份，客户端也通过暴露客户端证书来向服务器证明其身份。与仅证明服务器身份的正常 TLS/HTTPS 使用相比，这提供了更高的安全性。设置和维护相互认证——即提供新的证书和轮换过时的证书——被认为很复杂，因此很少使用。Istio 完全自动化了用于服务网格内部通信的相互认证的证书提供和轮换。这使得与手动设置相比，使用相互认证变得容易得多。

那么，我们为什么应该使用相互认证？仅仅保护外部 API 的 HTTPS 和 OAuth 2.0/OIDC 访问令牌难道还不够吗？

只要攻击是通过外部 API 发起的，可能就足够了。但如果 Kubernetes 集群中的一个 pods 被攻陷了会怎样呢？例如，如果攻击者控制了一个 pods，那么攻击者可以开始监听 Kubernetes 集群中其他 pods 之间的通信。如果内部通信以明文形式发送，攻击者将很容易获取集群中 pods 之间传输的敏感信息。为了尽量减少此类入侵造成的损害，可以使用相互认证来防止攻击者监听内部网络流量。

为了启用由 Istio 管理的相互认证的使用，Istio 需要在服务器端使用策略进行配置，在客户端使用目的地规则进行配置。

在使用 Istio 的演示配置时，如我们在*在 Kubernetes 集群中部署 Istio*一节中那样，我们创建了一个全局网格策略，配置服务器端使用宽容模式，这意味着 Istio 代理将允许明文和加密的请求。这可以通过以下命令来验证：

```java
kubectl get meshpolicy default -o yaml
```

期望的回答与以下类似：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/adef0bf8-61fd-484e-854c-a07e50609603.png)

为了使微服务在向其他微服务内部发送请求时使用相互认证，需要为每个微服务创建一个目的地规则。这是在`kubernetes/services/base/istio/internal_mtls_destination_rules.yml`文件中完成的。目的地规则看起来都一样；例如，对于`product-composite`服务，它们如下所示：

```java
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: product-composite-dr
spec:
  host: product-composite
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
```

`trafficPolicy` 设置为使用 `tls` 与 `ISTIO_MUTUAL`，这意味着相互认证是由 Istio 管理的。

目的地规则是在前面的*运行创建服务网格的命令*部分中使用 `kubernetes/scripts/deploy-dev-env.bash` 部署脚本时应用的。

为了验证内部通信是否得到保护，请执行以下步骤：

1.  确保在前面的*观察服务网格*部分中启动的负载测试仍在运行。

1.  在网络浏览器中打开 Kiali 图([`kiali.istio-system.svc.cluster.local:20001/kiali`](http://kiali.istio-system.svc.cluster.local:20001/kiali))。

1.  点击显示按钮以启用安全标签。图表将在所有由 Istio 自动相互认证保护的通信链路上显示一个锁，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/cc3e1088-449c-4140-8da3-9d90d416f1ab.png)

期望所有链接上都有一个锁，除了那些到资源管理器的链接——RabbitMQ、MySQL 和 MongoDB。

对 RabbitMQ、MySQL 和 MongoDB 的调用不由 Istio 代理处理，因此需要手动配置以使用 TLS 进行保护。

有了这些，我们已经看到了 Istio 中所有三种安全机制的实际应用，现在该看看 Istio 是如何帮助我们验证服务网格具有弹性的。

# 确保服务网格具有弹性

在本节中，我们将学习如何使用 Istio 确保服务网格具有弹性；也就是说，它能够处理服务网格中的临时故障。Istio 提供了类似于 Spring Framework 在超时、重试以及称为**异常检测**的类型断路器方面的机制来处理临时故障。当涉及到决定是否使用语言原生机制来处理临时故障，或者是否将此任务委托给如 Istio 的服务网格时，我倾向于使用语言原生机制，如在第十三章、*使用 Resilience4J 提高弹性*中的例子所示。在许多情况下，将处理错误的逻辑与其他微服务业务逻辑保持在一起是很重要的，例如为断路器处理回退选项。

在 Istio 中相应的机制可以提供很大帮助的情况。例如，如果一个微服务被部署，并且确定它不能处理在生产中偶尔发生的临时故障，那么使用 Istio 添加一个超时或重试机制而不是等待具有相应错误处理功能的微服务新版本发布将非常方便。

随着 Istio 而来的弹性方面的另一个功能是向现有服务网格注入故障和延迟的能力。为什么有人想这么做呢？

以受控的方式注入故障和延迟非常有用，可以验证微服务中的弹性能力是否如预期工作！我们将在本节中尝试它们，验证 `product-composite` 微服务中的重试、超时和断路器是否如预期工作。

在第十三章 *使用 Resilience4j 提高韧性* 中（参考 *在微服务源代码中添加可编程延迟和随机错误* 部分），我们添加了对在微服务源代码中注入故障和延迟的支持。最好使用 Istio 的功能在运行时注入故障和延迟，如下所示。

我们将首先注入故障，以查看 `product-composite` 微服务中的重试机制是否按预期工作。之后，我们将延迟产品服务的响应，并验证断路器如何按预期处理延迟。

# 通过注入故障测试弹性

让我们让产品服务抛出随机错误，并验证微服务架构是否正确处理此情况。我们期望 `product-composite` 微服务中的重试机制启动，并重试请求，直到成功或达到最大重试次数限制。这将确保短暂故障不会比重试尝试引入的延迟对最终用户产生更大影响。参考第十三章 *使用 Resilience4j 提高韧性* 中的 *添加重试机制* 部分，回顾 `product-composite` 微服务中的重试机制。

可以使用 `kubernetes/resilience-tests/product-virtual-service-with-faults.yml` 注入故障。这如下所示：

```java
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: product-vs
spec:
  hosts:
    - product
  http:
  - route:
    - destination:
        host: product
    fault:
 abort:
        httpStatus: 500
        percent: 20
```

定义说明，发送到产品服务的 20%的请求应使用 HTTP 状态码 500（内部服务器错误）终止。

执行以下步骤以测试此功能：

1.  确保正在运行使用 `siege` 的负载测试，如在第 *观察服务网格* 节中启动。

1.  使用以下命令应用故障注入：

```java
kubectl apply -f kubernetes/resilience-tests/product-virtual-service-with-faults.yml
```

1.  监控 `siege` 负载测试工具的输出。期望输出类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/0bc01f04-88dd-4507-8e09-21be25135194.png)

从样本输出中，我们可以看到所有请求仍然成功，换句话说，返回状态 200（OK）；然而，其中一些（20%）需要额外一秒钟才能完成。这表明 `product-composite` 微服务中的重试机制已经启动，并重试了发送到产品服务的失败请求。

1.  Kiali 也会指示产品服务收到的请求存在问题，如下所示：

    1.  前往我们之前用于观察我们命名空间 `hands-on` 中的流量的 Kiali web UI 的调用图。

    1.  点击显示菜单按钮，选择服务节点。

    1.  点击显示按钮左侧的菜单按钮，名为无边缘标签，然后选择响应时间选项。

+   1.  图表将显示如下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ee4ac35f-e8a5-437f-b1de-261228e0ed60.png)

服务节点产品的箭头将显示为红色，以指示检测到失败请求。如果我们点击箭头，可以在右侧看到故障统计。

在前面的示例屏幕截图中，报告的错误率为 19.4%，与我们要求的 20%相符。请注意，从 Istio 网关到`product-composite`服务的箭头仍然是绿色的。这意味着`product-composite`服务中的重试机制保护了终端用户；换句话说，故障不会传播到终端用户。

使用以下命令结束故障注入的移除：

```java
kubectl delete -f kubernetes/resilience-tests/product-virtual-service-with-faults.yml
```

现在让我们进入下一节，在那里我们将注入延迟以触发电路断路器。

# 通过注入延迟来测试弹性

从第十三章，*使用 Resilience4j 提高弹性*（参考*介绍电路断路器*部分），我们知道电路断路器可以用来防止服务响应缓慢或服务根本不响应的问题。

让我们通过向`product-composite`服务中注入延迟来验证电路断路器是否按预期工作。可以使用虚拟服务注入延迟。

请参考`kubernetes/resilience-tests/product-virtual-service-with-delay.yml`。其代码如下所示：

```java
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: product-vs
spec:
  hosts:
    - product
  http:
  - route:
    - destination:
        host: product
    fault:
      delay:
        fixedDelay: 3s
        percent: 100
```

前面的定义说明所有发送到产品服务的请求都应延迟 3 秒。

从`product-composite`服务发送到产品服务的请求配置为在 2 秒后超时。如果连续三次请求失败，电路断路器配置为打开电路。当电路打开时，它将快速失败；换句话说，它将立即抛出异常，不尝试调用底层服务。`product-composite`微服务中的业务逻辑将捕获此异常并应用回退逻辑。回顾一下，请参阅第十三章，*使用 Resilience4j 提高弹性*（参考*添加电路断路器*部分）。

通过以下步骤测试通过注入延迟的电路断路器：

1.  通过在运行`siege`的终端窗口中按下`Ctrl + C`命令来停止负载测试运行。

1.  使用以下命令在产品服务中创建临时延迟：

```java
kubectl apply -f kubernetes/resilience-tests/product-virtual-service-with-delay.yml
```

1.  如下获取访问令牌：

```java
ACCESS_TOKEN=$(curl -k https://writer:secret@minikube.me/oauth/token -d grant_type=password -d username=magnus -d password=password -s | jq .access_token -r)
```

1.  连续发送六个请求。期望在第一次三次失败调用后打开电路，电路断路器对最后三次调用应用快速失败逻辑，并返回回退响应，如下所示：

```java
for i in {1..6}; do time curl -k https://minikube.me/product-composite/2 -H "Authorization: Bearer $ACCESS_TOKEN"; done
```

前三次调用的响应预期会出现与超时相关的错误信息，响应时间为 2 秒，换句话说，就是超时时间。期望前三次调用的响应类似于以下内容：

**![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/c61d561d-e023-488b-9e75-1dbb32bd2f5c.png)**

最后 3 次调用的响应预计将是回退逻辑的响应，响应时间短。期待最后 3 次调用的响应如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/468fa43c-0a38-47fa-8baf-80de72b55711.png)

1.  通过以下命令删除临时延迟来模拟延迟问题已解决：

```java
kubectl delete -f kubernetes/resilience-tests/product-virtual-service-with-delay.yml
```

1.  通过使用前一个命令发送新请求，验证正确答案再次返回，且没有任何延迟。

如果您想检查熔断器的状态，您可以使用以下命令：

`curl product-composite.hands-on.svc.cluster.local:4004/actuator/health -s | jq -r .details.productCircuitBreaker.details.state`

它应该报告`CLOSED`，`OPEN`或`HALF_OPEN`，具体取决于其状态。

这证明了我们使用 Istio 注入延迟时，熔断器按预期反应。这结束了在 Istio 中测试可以验证微服务架构具有弹性的功能。我们将在 Istio 中探索的最后一项功能是其对流量管理的支持；我们将了解如何使用它来实现零停机部署。

# 执行零停机部署

正如在第十六章中提到的*将我们的微服务部署到 Kubernetes*（请参阅*执行滚动升级*部分），随着越来越多的自治微服务独立于彼此进行更新，能够在不停机的情况下部署更新变得至关重要。

在本节中，我们将学习 Istio 的流量管理和路由功能，以及如何使用它们来执行微服务的全新版本的部署，而不需要任何停机时间。在第十六章中，我们看到了 Kubernetes 如何用来执行滚动升级而不需要停机。（请参阅*执行滚动升级*部分）。使用 Kubernetes 的滚动升级机制可以自动化整个过程，但不幸的是，它提供了一个测试新版本的机会，在所有用户都被路由到新版本之前。

使用 Istio，我们可以部署新版本，但最初将所有用户路由到现有版本（在本章中称为旧版本）。在那之后，我们可以使用 Istio 的精细路由机制来控制用户如何被路由到新旧版本。我们将了解如何使用 Istio 实现两种流行的升级策略：

+   **金丝雀部署*: 当使用金丝雀部署时，大多数用户被路由到旧版本，除了被选中的测试用户被路由到新版本。当测试用户批准了新版本，可以使用蓝/绿部署将普通用户路由到新版本。

+   **蓝/绿** **部署**：传统上，蓝/绿部署意味着所有用户都被切换到蓝色或绿色版本之一，一个是新版本，另一个是旧版本。如果切换到新版本时出现问题，很容易切换回旧版本。使用 Istio，可以通过逐渐将用户切换到新版本来优化此策略，例如，从 20%的用户开始，然后逐渐增加被路由到新版本的用户百分比。在任何时候，如果新版本中揭示了致命错误，很轻易地将所有用户路由回旧版本。

正如在第十六章《将我们的微服务部署到 Kubernetes》（参考*执行滚动升级*部分）中提到的，这些升级策略的一个重要前提是升级是向后兼容的。这种升级在 API 和消息格式上都兼容，这些是与其他服务和数据库结构通信所使用的。如果微服务的新版本需要对外部 API、消息格式或数据库结构进行更改，而旧版本无法处理，则无法应用这些升级策略。

我们将在以下子节中逐步部署以下部署场景：

+   我们首先部署`v1`和`v2`版本的微服务，路由配置为将所有请求发送到`v1`版本的微服务。

+   接下来，我们将允许一个测试组运行金丝雀测试；也就是说，我们将验证微服务的新的`v2`版本。为了简化测试，我们将只将测试用户路由到核心微服务的新版本，即`product`、`recommendation`和`review`微服务。

+   最后，我们将开始使用蓝/绿部署将普通用户切换到新版本：最初是一小部分用户，然后随着时间的推移，越来越多的用户，直到最终所有用户都被路由到新版本。我们还将了解如何在检测到新 v2 版本中的致命错误时，快速切换回`v1`版本。

首先，让我们看看为了部署两个并发版本的微服务（`v1`和`v2`），源代码中已经应用了哪些更改。

# 源代码更改

正如在*改变 Kubernetes 定义文件的文件结构*章节中提到的，为了支持在生产环境中部署微服务的并发版本，在本章中`kubernetes/services`中的 Kubernetes 定义文件的文件结构进行了扩展。扩展后的文件结构如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/26f33b74-c0c1-46ea-80f3-259b536c3bf8.png)

前述图表中已经移除了有关开发环境的具体细节。

首先让我们看看微服务`v1`和`v2`版本的服务和部署对象是如何配置和创建的。之后，我们将查看用于控制路由的 Istio 对象的附加定义文件。

# 微服务并发版本的服务和部署对象

为了能够同时运行微服务的多个版本，部署对象及其相应的 pods 必须有不同的名称，例如`product-v1`和`product-v2`。然而，每个微服务只能有一个 Kubernetes 服务对象。所有特定微服务的流量总是通过一个相同的 service 对象，无论请求最终会被路由到哪个版本的 pods。这是通过将部署对象和服务对象分成不同的文件夹来使用 Kustomize 实现的。

为了给部署对象及其 pods 赋予版本依赖的名称，`kustomization.yml`文件可以使用`nameSuffix`指令告诉 Kustomize 在它创建的所有 Kubernetes 对象上添加给定后缀。例如，用于`v1`版本的微服务在`kubernetes/services/overlays/prod/v1`文件夹中的`kustomization.yml`文件如下所示：

```java
nameSuffix: -v1
bases:
- ../../../base/deployments
patchesStrategicMerge:
- ...
```

`nameSuffix: -v1`设置会导致使用这个`kustomization.yml`文件创建的所有对象都带有`-v1`后缀。

为了创建没有版本后缀的对象，以及具有`v1`和`v2`版本后缀的部署对象及其 pods，`kubernetes/scripts/deploy-prod-env.bash`部署脚本执行单独的`kubectl apply`命令，如下所示：

```java
kubectl apply -k kubernetes/services/base/services
kubectl apply -k kubernetes/services/overlays/prod/v1
kubectl apply -k kubernetes/services/overlays/prod/v2
```

我们再看看我们都添加了哪些 Istio 定义文件来配置路由规则。

# 添加了用于 Istio 的 Kubernetes 定义文件。

为了配置路由规则，我们将向`kubernetes/services/overlays/prod/istio`文件夹添加 Istio 对象。每个微服务都有一个虚拟服务对象，定义了旧版本和新版本之间的路由权重分布。最初，它被设置为将 100%的流量路由到旧版本。例如，产品微服务在`product-routing-virtual-service.yml`中的路由规则如下所示：

```java
  http:
  - route:
    - destination:
        host: product
        subset: old
      weight: 100
    - destination:
        host: product
        subset: new
      weight: 0
```

虚拟服务定义了旧版本和新版本的子集。为了定义旧版本和新版本实际的版本，每个微服务也定义了一个目的地规则。目的地规则详细说明了如何识别旧子集和新子集，例如，在`old_new_subsets_destination_rules.yml`中的产品微服务：

```java
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: product-dr
spec:
  host: product
  subsets:
  - name: old
    labels:
      version: v1
  - name: new
    labels:
      version: v2
```

名为`old`的子集指向标签`version`设置为`v1`的产品 pods，而名为`new`的子集指向标签`version`设置为`v2`的 pods。

为了将流量路由到特定版本，Istio 文档建议将 pod 标记为名为 `version` 的标签以标识其版本。 有关详细信息，请参阅 [`istio.io/docs/setup/kubernetes/additional-setup/requirements/`](https://istio.io/docs/setup/kubernetes/additional-setup/requirements/)。

最后，为了支持金丝雀测试人员，在三个核心微服务（`product`、`recommendation` 和 `review`）的虚拟服务中添加了一个额外的路由规则。 此路由规则说明，任何带有名为 `X-group` 的 HTTP 头的 incoming 请求设置为值 `test` 总是会路由到服务的新版本。 它如下所示：

```java
  http:
  - match:
    - headers:
        X-group:
          exact: test
    route:
    - destination:
        host: product
        subset: new
```

`match` 和 `route` 部分指定，带有 HTTP 头 `X-group` 设置为 `test` 值的请求将被路由到名为 `new` 的子集中。

为了创建这些 Istio 对象，`kubernetes/scripts/deploy-prod-env.bash` 部署脚本执行了以下命令：

```java
kubectl apply -k kubernetes/services/overlays/prod/istio
```

最后，为了能够基于基于头部的路由将金丝雀测试人员路由到新版本，`product-composite` 微服务已更新以转发 HTTP 头 `X-group`。 有关详细信息，请参阅 `se.magnus.microservices.composite.product.services.ProductCompositeServiceImpl` 类中的 `getCompositeProduct()` 方法。

现在，我们已经看到了源代码的所有更改，我们准备部署微服务的 v1 和 v2 版本。

# 部署带有路由到 v1 版本的 v1 和 v2 版本的微服务

为了能够测试微服务的 `v1` 和 `v2` 版本，我们需要删除本章前面一直在使用的开发环境，并创建一个生产环境，我们可以在其中部署 `v1` 和 `v2` 版本的微服务。

为了实现这一点，请运行以下命令：

1.  重新创建 `hands-on` 命名空间：

```java
kubectl delete namespace hands-on
kubectl create namespace hands-on
```

1.  通过运行以下命令来执行部署脚本：

```java
./kubernetes/scripts/deploy-prod-env.bash 
```

该命令需要几分钟时间，最终应如下列出所有 v1 或 v2 版本的 pod：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/3ac160f5-b56c-46fd-8d26-d0cad647e4d5.png)

1.  执行以下常规测试以验证一切是否正常工作：

```java
SKIP_CB_TESTS=true ./test-em-all.bash
```

如果在此命令执行后立即执行 `deploy` 命令，有时会失败。 只需重新运行命令，它应该会正常运行！

由于我们现在为每个微服务运行了两个 pod（V1 和 V2 版本），因此电路测试不再工作。 这是因为测试脚本无法控制它通过 Kubernetes 服务与哪个 pod 进行通信。 测试脚本通过 `product-composite` 微服务的 actuator 端口 `4004` 查询电路 breaker 的状态。 此端口不由 Istio 管理，因此其路由规则不适用。 测试脚本因此不知道它是在检查 `product-composite` 微服务的 V1 或 V2 版本的电路 breaker 状态。 我们可以通过使用 `SKIP_CB_TESTS=true` 标志来跳过电路测试。

期望输出类似于我们在前几章中看到的内容，但排除熔断器测试：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/4ebb9d21-ccfc-4210-92a0-8be37b37fd74.png)

我们现在准备好运行一些*零停机部署*测试。首先，让我们验证所有流量都路由到了微服务的 v1 版本！

# 验证所有流量最初都路由到 v1 版本的微服务

为了验证所有请求都被路由到微服务的 v1 版本，我们将启动负载测试工具`siege`，然后观察通过服务网格使用 Kiali 流动的流量。

执行以下步骤：

1.  获取一个新的访问令牌并启动`siege`负载测试工具，使用以下命令：

```java
ACCESS_TOKEN=$(curl -k https://writer:secret@minikube.me/oauth/token -d grant_type=password -d username=magnus -d password=password -s | jq .access_token -r)

siege https://minikube.me/product-composite/2 -H "Authorization: Bearer $ACCESS_TOKEN" -c1 -d1
```

1.  在 Kiali 的 Web UI 中转到图表视图([`kiali.istio-system.svc.cluster.local:20001/kiali`](http://kiali.istio-system.svc.cluster.local:20001/kiali)):

    1.  点击显示菜单按钮并取消选择服务节点。

    1.  在一两分钟后，期望只有以下 v1 版本的微服务流量：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/e2170279-e949-462e-b545-b0b5c6c69d54.png)

太好了！这意味着尽管已经部署了微服务的 v2 版本，但它们并没有获得任何路由到的流量。现在让我们尝试进行金丝雀测试，其中选定的测试用户被允许尝试微服务的 v2 版本！

# 运行金丝雀测试

要运行金丝雀测试，换句话说，即所有其他用户仍然被路由到部署的微服务的旧版本时，我们需要在我们的对外 API 请求中添加`X-group`HTTP 头，设置为`test`值。

要查看响应了请求的微服务的哪个版本，可以检查响应中的`serviceAddresses`字段。`serviceAddresses`字段包含每个参与创建响应的服务的主机名。主机名等于 pods 的名称，因此我们可以通过主机名找到版本；例如，对于版本 V1 的产品服务，主机名为`product-v1-...`，对于版本 V2 的产品服务，主机名为`product-v2-...`。

首先，发送一个正常请求并验证是微服务的 v1 版本响应了我们的请求。接下来，发送一个`X-group`HTTP 头设置为`test`值的请求，并验证新的 v2 版本正在响应。

为此，执行以下步骤：

1.  发送一个正常请求以验证请求被路由到微服务的 v1 版本，使用`jq`过滤掉响应中的`serviceAddresses`字段：

```java
curl -ks https://minikube.me/product-composite/2 -H "Authorization: Bearer $ACCESS_TOKEN" | jq .serviceAddresses
```

期望得到如下类似的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/661a5a65-6610-40c6-aaf4-5a55f2e57b81.png)

正如预期的那样，所有三个核心服务都是微服务的 v1 版本。

1.  如果我们添加了`X-group=test`头，我们期望请求由核心微服务的 v2 版本处理。运行以下命令：

```java
curl -ks https://minikube.me/product-composite/2 -H "Authorization: Bearer $ACCESS_TOKEN" -H "X-group: test" | jq .serviceAddresses
```

期望得到如下类似的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/1f63113a-ae33-446b-bdde-05fa4cf621c6.png)

如预期那样，现在所有三个核心微服务都是 v2 版本；也就是说，作为金丝雀测试员，我们被路由到新的 v2 版本！

考虑到金丝雀测试返回了预期结果，我们准备允许普通用户通过蓝/绿部署路由到新的 v2 版本。

# 运行蓝/绿测试

为了将部分普通用户路由到微服务的新的 v2 版本，我们必须修改虚拟服务中的权重分布。目前它们是 100/0；也就是说，所有流量都被路由到旧的 v1 版本。我们可以像以前一样实现这一点，即通过编辑`kubernetes/services/overlays/prod/istio`文件夹中虚拟服务的定义文件，然后运行`kubectl apply`命令以使更改生效。作为一种替代方案，我们可以使用`kubectl patch`命令直接在 Kubernetes API 服务器中的虚拟服务对象上更改权重分布。

我发现 patch 命令在要对同一对象进行许多更改以尝试某些东西时很有用，例如，更改路由规则中的权重分布。在本节中，我们将使用`kubectl patch`命令快速更改微服务 v1 和 v2 版本之间的路由规则的权重分布。要在一系列`kubectl patch`命令执行后获取虚拟服务的状态，可以发出类似于`kubectl get vs NNN -o yaml`的命令。例如，要获取产品微服务的虚拟服务状态，可以发出以下命令：`kubectl get vs product-vs -o yaml`。

由于我们以前没有使用过`kubectl patch`命令，而且一开始可能会有些复杂，因此在执行绿/蓝部署之前，让我们先简要介绍它的工作原理。

# 简要介绍 kubectl patch 命令

`kubectl patch`命令可用于在 Kubernetes API 服务器中更新现有对象的具体字段。我们将尝试在名为`review-vs`的评论微服务的虚拟服务上使用 patch 命令。虚拟服务`review-vs`的定义的相关部分如下所示：

```java
spec:
  http:
  - match:
    ...
  - route:
    - destination:
        host: review
        subset: old
      weight: 100
    - destination:
        host: review
        subset: new
      weight: 0 
```

完整的源代码请参阅`kubernetes/services/overlays/prod/istio/review-routing-virtual-service.yml`。

一个改变`review`微服务中路由到 v1 和 v2 容器的权重分布的示例 patch 命令如下所示：

```java
kubectl patch virtualservice review-vs --type=json -p='[
 {"op": "add", "path": "/spec/http/1/route/0/weight", "value": "80"},
 {"op": "add", "path": "/spec/http/1/route/1/weight", "value": "20"}
]'
```

该命令将配置评论微服务的路由规则，将 80%的请求路由到旧版本，将 20%的请求路由到新版本。

为了指定`weight`值将在`review-vs`虚拟服务中更改，旧版本给出了`/spec/http/1/route/0/weight`路径，新版本给出`/spec/http/1/route/1/weight`。

路径中的`0`和`1`用于指定虚拟服务定义中数组元素的索引。例如，`http/1`意味着在`http`元素下的第二个元素。请参阅前面的`review-vs`虚拟服务的定义。

从前面的定义中我们可以看出，第二个元素是`route`元素。第一个元素，索引为`0`的是匹配元素。

现在我们已经对`kubectl patch`命令有了更多的了解，我们准备测试蓝绿部署。

# 执行蓝绿部署

现在，是逐渐让更多用户使用蓝绿部署转移到新版本的时候了。要执行部署，请按照以下步骤操作：

1.  确保负载测试工具`Siege`仍在运行。

    它是在前面的*验证所有流量最初都发送到微服务的 v1 版本*部分启动的。

1.  为了将 20%的用户路由到新的 v2 版本的`review`微服务，我们可以修补虚拟服务，并使用以下命令更改权重：

```java
kubectl patch virtualservice review-vs --type=json -p='[
 {"op": "add", "path": "/spec/http/1/route/0/weight", "value": 
  "80"},
 {"op": "add", "path": "/spec/http/1/route/1/weight", "value":  
  "20"}
 ]'
```

1.  为了观察路由规则的变化，请前往 Kiali web UI([`kiali.istio-system.svc.cluster.local:20001/kiali`](http://kiali.istio-system.svc.cluster.local:20001/kiali))并选择图表视图。

1.  将边缘标签更改为`请求百分比`。

1.  在 Kiali 中更新统计数据之前等待一分钟，这样我们就可以观察到变化。期望 Kiali 中的图表显示如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a610a4da-ad35-4bbd-ab61-f30f72241355.png)

取决于你等待了多长时间，图表可能看起来会有点不同！

在截图中，我们可以看到 Istio 现在将流量路由到`review`微服务的 v1 和 v2 版本。

从`product-composite`微服务发送到`review`微服务的 33%流量中，7%被路由到新的 v2 pod，26%到旧的 v1 pod。这意味着有 7/33（=21%）的请求被路由到 v2 pod，有 26/33（=79%）被路由到 v1 pod。这与我们请求的 20/80 分布相符：

1.  请随意尝试前面的`kubectl patch`命令，以影响其他核心微服务（`product`和`recommendation`）的路由规则：

1.  如果你想将所有流量路由到所有微服务的 v2 版本，你可以运行以下脚本：

```java
./kubernetes/scripts/route-all-traffic-to-v2-services.bash
```

你必须给 Kiali 一分钟左右的时间来收集指标，然后它才能可视化微服务 v1 和 v2 版本之间的路由变化，但请记住，实际路由的变化是即时的！

过了一会儿，期望微服务图中的只有 v2 版本显示出来：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/fafbc4a4-4e90-47d5-8a5f-b933a548edf3.png)

取决于你等待了多长时间，图表可能看起来会有点不同！

1.  如果升级到 v2 后出现严重问题，以下命令可以执行以将所有流量恢复到所有微服务的 v1 版本：

```java
./kubernetes/scripts/route-all-traffic-to-v1-services.bash
```

经过一段时间后，Kiali 中的图表应该看起来像前文*验证微服务初始所有流量都发送到 v1 版本*部分所示的截图；也就是说，再次可视化所有请求都发送到所有微服务的 v1 版本。

这结束了服务网格概念和作为概念实现的 Istio 的介绍。

在我们结束本章之前，让我们回顾一下我们如何使用 Docker Compose 运行测试，以确保我们的微服务源代码不依赖于在 Kubernetes 中的部署。

# 使用 Docker Compose 运行测试

如第十七章所述，*实施 Kubernetes 特性作为替代*（参考*验证微服务在没有 Kubernetes 的情况下是否工作*部分），从功能角度确保微服务的源代码不依赖于 Kubernetes 或 Istio 这样的平台是很重要的。

为了验证在没有 Kubernetes 和 Istio 的情况下微服务是否按预期工作，请按照第一章 7 节*，实施 Kubernetes 特性作为替代*（参考*使用 Docker Compose 测试*部分）所述运行测试。由于测试脚本`test-em-all.bash`的默认值已如前所述在*运行创建服务网格的命令*部分更改，因此在使用 Docker Compose 时必须设置以下参数：`HOST=localhost PORT=8443 HEALTH_URL=https://localhost:8443`。例如，要使用默认的 Docker Compose 文件`docker-compose.yml`运行测试，请运行以下命令：

```java
HOST=localhost PORT=8443 HEALTH_URL=https://localhost:8443 ./test-em-all.bash start stop
```

测试应如之前所述，首先启动所有容器；然后运行测试，最后停止所有容器。关于预期输出的详细信息，请参见第十七章，*实施 Kubernetes 特性作为替代*（参考*验证微服务在没有 Kubernetes 的情况下是否工作*部分）。

在成功使用 Docker Compose 执行测试后，我们验证了微服务在功能上既不依赖于 Kubernetes 也不依赖于 Istio。这些测试结论了使用 Istio 作为服务网格的章节。

# 总结

在本章中，我们学习了服务网格概念以及实现该概念的开源项目 Istio。服务网格为处理系统微服务景观中的挑战提供了能力，如安全、策略执行、弹性和流量管理。服务网格还可以通过可视化微服务之间的流量来使微服务景观可观测。

对于可观测性，Istio 使用了 Kiali、Jaeger 和 Grafana（关于 Grafana 的更多信息请参见第二十章，*监控微服务*）。当谈到安全性时，Istio 可以配置为使用证书来保护使用 HTTPS 的外部 API，并要求外部请求包含有效的基于 JWT 的 OAuth 2.0/OIDC 访问令牌。最后，Istio 可以配置为使用**相互认证**（**mTLS**）来自动保护内部通信。

为了弹性和健壮性，Istio 提供了处理重试、超时和类似于断路器的异常检测机制的机制。在许多情况下，如果可能的话，在微服务的源代码中实现这些弹性能力是更好的。Istio 注入故障和延迟的能力对于验证服务网格中的微服务作为一个弹性和健壮的系统景观一起工作非常有用。Istio 还可以用于处理零停机部署。使用其细粒度的路由规则，可以执行金丝雀和蓝/绿部署。

我们还没有涉及的一个重要领域是如何收集和分析由所有微服务实例创建的日志文件。在下一章中，我们将了解如何使用流行的工具堆栈，即基于 Elasticsearch、Fluentd 和 Kibana 的 EFK 堆栈，来完成这项工作。

# 问题

1.  服务网格中的代理组件有什么作用？

1.  服务网格中的控制平面和数据平面有什么区别？

1.  `istioctl kube-inject`命令是用来做什么的？

1.  `minikube tunnel`命令是用来做什么的？

1.  Istio 中用于可观测性的工具有哪些？

1.  为了让 Istio 使用相互认证来保护服务网格内的通信，需要进行哪些配置？

1.  在虚拟服务中，`abort`和`delay`元素可以用来做什么？

1.  设置蓝/绿部署场景需要进行哪些配置？
