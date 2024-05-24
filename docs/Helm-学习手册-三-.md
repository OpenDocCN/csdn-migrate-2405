# Helm 学习手册（三）

> 原文：[`zh.annas-archive.org/md5/AB61831A08B0763334412D2ABCB093BB`](https://zh.annas-archive.org/md5/AB61831A08B0763334412D2ABCB093BB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：测试 Helm 图表

测试是工程师在软件开发过程中必须执行的常见任务。测试是为了验证产品的功能性，以及在产品随着时间的推移而发展时防止回归。经过充分测试的软件更容易随着时间的推移进行维护，并允许开发人员更有信心地向最终用户提供新版本。

为了确保 Helm 图表能够按预期的质量水平提供其功能，应该对其进行适当的测试。在本章中，我们将讨论如何实现强大的 Helm 图表测试，包括以下主题：

+   设置您的环境

+   验证 Helm 模板

+   在一个实时集群中进行测试

+   通过图表测试项目改进图表测试

+   清理

# 技术要求

本章将使用以下技术：

+   `minikube`

+   `kubectl`

+   `helm`

+   `git`

+   `yamllint`

+   `yamale`

+   `chart-testing` (`ct`)

除了这些工具，您还可以在 Packt GitHub 存储库中跟随示例，该存储库位于[`github.com/PacktPublishing/-Learn-Helm`](https://github.com/PacktPublishing/-Learn-Helm)，本章将引用该存储库。在本章中使用的许多示例命令中，我们将引用 Packt 存储库，因此您可能会发现通过运行`git clone`命令克隆此存储库会很有帮助：

```
$ git clone https://github.com/PacktPublishing/-Learn-Helm Learn-Helm
```

现在，让我们继续设置您的本地`minikube`环境。

# 设置您的环境

在本章中，我们将为上一章创建的`Guestbook`图表创建并运行一系列测试。运行以下步骤来设置您的`minikube`环境，在这里我们将测试 Guestbook 图表：

1.  通过运行`minikube start`命令启动`minikube`：

```
minikube start
```

1.  然后，创建一个名为`chapter6`的新命名空间：

```
kubectl create namespace chapter6
```

准备好您的`minikube`环境后，让我们开始讨论如何测试 Helm 图表。我们将首先讨论您可以使用的方法来验证您的 Helm 模板。

# 验证 Helm 模板

在上一章中，我们从头开始构建了一个 Helm 图表。最终产品非常复杂，包含参数化、条件模板和生命周期钩子。由于 Helm 的主要目的之一是创建 Kubernetes 资源，因此在将资源模板应用到 Kubernetes 集群之前，您应该确保这些资源模板被正确生成。这可以通过多种方式来完成，我们将在下一节中讨论。

## 使用 helm template 在本地验证模板生成

验证图表模板的第一种方法是使用`helm template`命令，该命令可用于在本地呈现图表模板并在标准输出中显示其完全呈现的内容。

`helm template`命令具有以下语法：

```
$ helm template [NAME] [CHART] [flags]
```

此命令在本地呈现模板，使用`NAME`参数满足`.Release`内置对象，使用`CHART`参数表示包含 Kubernetes 模板的图表。Packt 存储库中的`helm-charts/charts/guestbook`文件夹可用于演示`helm template`命令的功能。该文件夹包含在上一节中开发的图表，以及稍后在本章中将使用的其他资源。

通过运行以下命令在本地呈现`guestbook`图表：

```
$ helm template my-guestbook Learn-Helm/helm-charts/charts/guestbook
```

此命令的结果将显示每个 Kubernetes 资源，如果将其应用于集群，将会创建这些资源，如下所示：

![图 6.1 - 用于 guestbook 图表的 ConfigMap](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.1.jpg)

图 6.1 - "helm template"输出

前面的屏幕截图显示了针对上一章中创建的 Guestbook 图表执行的`helm template`命令的输出的开始部分。正如您所看到的，显示了一个完全呈现的`ConfigMap`，以及另一个`ConfigMap`的开始，该`ConfigMap`是使用该版本创建的。在本地呈现这些资源可以让您了解如果将该版本安装到 Kubernetes 集群中，将会创建哪些确切的资源和规范。

在图表开发过程中，您可能希望定期使用`helm template`命令来验证您的 Kubernetes 资源是否被正确生成。

您可能想要验证图表开发的一些常见方面，包括以下内容：

+   参数化字段成功地被默认值或覆盖值替换

+   控制操作，如`if`、`range`和`with`，根据提供的值成功生成 YAML 文件

+   资源包含适当的间距和缩进

+   函数和管道被正确使用以正确格式化和操作 YAML 文件

+   诸如`required`和`fail`之类的函数根据用户输入正确验证值

了解图表模板如何在本地呈现后，现在让我们深入一些特定方面，您可以通过利用`helm template`命令进行测试和验证。

### 测试模板参数化

重要的是要检查模板的参数是否成功填充了值。这很重要，因为您的图表可能由多个不同的值组成。您可以通过确保每个值具有合理的默认值或具有验证来确保您的图表被正确参数化，如果未提供值，则验证失败图表呈现。

想象以下部署：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
  replicas: {{ .Values.replicas }}
<skipping>
          ports:
            - containerPort: {{ .Values.port }}
```

在图表的`values.yaml`文件中应定义`replicas`和`port`值的合理默认值，如下所示：

```
replicas: 1
port: 8080
```

运行`helm template`命令针对此模板资源呈现以下部署，将`replicas`和`port`值替换为它们的默认值：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
  replicas: 1
<skipping>
          ports:
            - containerPort: 8080
```

`helm template`的输出允许您验证参数是否被其默认值正确替换。您还可以通过向`helm template`命令传递`--values`或`--set`参数来验证提供的值是否成功覆盖：

```
$ helm template my-chart $CHART_DIRECTORY --set replicas=2
```

生成的模板反映了您提供的值：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
  replicas: 2
<skipping>
          ports:
            - containerPort: 8080
```

虽然具有默认设置的值通常很容易通过`helm template`进行测试，但更重要的是测试需要验证的值，因为无效的值可能会阻止图表正确安装。

您应该使用`helm template`来确保具有限制的值，例如仅允许特定输入的值，通过`required`和`fail`函数成功验证。

想象以下部署模板：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
  replicas: {{ .Values.replicas }}
<skipping>
      containers:
        - name: main
          image: {{ .Values.imageRegistry }}/{{ .Values.imageName }}
          ports:
            - containerPort: {{ .Values.port }}
```

如果此部署属于具有相同`values`文件的图表，并且您期望用户提供`imageRegistry`和`imageName`值来安装图表，如果您然后使用`helm template`命令而不提供这些值，则结果不尽如人意，如下输出所示：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
  replicas: 1
<skipping>
      containers:
        - name: main
          image: /
          ports:
            - containerPort: 8080
```

由于没有设置门控，呈现的结果是一个具有无效图像的部署，`/`。因为我们使用了`helm template`进行测试，所以我们知道需要处理这些值未定义的情况。可以通过使用`required`函数来提供验证，以确保这些值被指定：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
  replicas: {{ .Values.replicas }}
<skipping>
      containers:
        - name: main
          image: {{ required 'value 'imageRegistry' is required' .Values.imageRegistry }}/{{ required 'value 'imageName' is required' .Values.imageName }}
          ports:
            - containerPort: {{ .Values.port }}
```

当对具有更新的部署模板的图表应用`helm template`命令时，结果会显示一条消息，指示用户提供模板引擎遇到的第一个缺失的值：

```
$ helm template my-chart $CHART_DIRECTORY
Error: execution error at (test-chart/templates/deployment.yaml:17:20): value 'imageRegistry' is required
```

您还可以通过在`helm template`命令旁边提供有效的值文件来进一步测试此验证。例如，我们假设以下值是在用户管理的`values`文件中提供的：

```
imageRegistry: my-registry.example.com
imageName: learnhelm/my-image
```

然后在执行以下命令时提供此文件：

```
$ helm template my-chart $CHART_DIRECTORY --values my-values.yaml
---
# Source: test-chart/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
<skipping>
  replicas: 1
<skipping>
      containers:
        - name: main
          image: my-registry.example.com/learnhelm/my-image
          ports:
            - containerPort: 8080
```

作为参数化的一般准则，请确保跟踪您的值，并确保每个值在您的图表中都有用到。在`values.yaml`文件中设置合理的默认值，并在无法设置默认值的情况下使用`required`函数。使用`helm template`函数确保值被正确渲染并产生期望的 Kubernetes 资源配置。

另外，您可能还希望考虑在您的`values.yaml`文件中包含必需的值，将其作为空字段，并在注释中指出它们是必需的。这样用户就可以查看您的`values.yaml`文件，并查看您的图表支持的所有值，包括他们必须自己提供的值。在添加了`imageRegistry`和`imageName`值后，考虑以下`values`文件：

```
replicas: 1
port: 8080
## REQUIRED
imageRegistry:
## REQUIRED
imageName:
```

尽管这些值写在您的图表的`values.yaml`文件中，但当`helm template`命令运行时，这些值仍然会评估为 null，提供与之前执行时相同的行为。不同之处在于现在您可以明确地看到这些值是必需的，因此当您首次尝试安装图表时，您不会感到惊讶。

接下来，我们将讨论如何在本地生成您的图表模板可以帮助您测试图表的控制操作。

### 测试控制操作

除了基本的参数化，您还应该考虑使用`helm template`命令来验证控制操作（特别是`if`和`range`）是否被正确处理以产生期望的结果。

考虑以下部署模板：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
{{- range .Values.env }}
          env:
            - name: {{ .name }}
              value: {{ .value }}
{{- end }}
{{- if .Values.enableLiveness }}
          livenessProbe:
            httpGet:
              path: /
              port: {{ .Values.port }}
            initialDelaySeconds: 5
            periodSeconds: 10
{{- end }}
          ports:
            containerPort: 8080
```

如果`env`和`enableLiveness`的值都是`null`，您可以通过运行`helm template`命令来测试此渲染是否仍然成功：

```
$ helm template my-chart $CHART_DIRECTORY --values my-values.yaml
---
# Source: test-chart/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
<skipping>
          ports:
            - containerPort: 8080
```

您会注意到`range`和`if`操作均未生成。对于`range`子句，空值或空值不会有任何条目对其进行操作，并且当提供给`if`操作时，这些值也被评估为`false`。通过向`helm template`提供`env`和`enableLiveness`值，您可以验证您已经正确编写了模板以使用这些操作生成 YAML。

您可以将这些值添加到一个`values`文件中，如下所示：

```
env:
  - name: BOOK
    value: Learn Helm
enableLiveness: true
```

进行这些更改后，验证`helm template`命令的期望结果，以证明模板已正确编写以使用这些值：

```
---
# Source: test-chart/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
<skipping>
          env:
            - name: BOOK
              value: Learn Helm
          livenessProbe:
            httpGet:
              path: /
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          ports:
            - containerPort: 8080
```

您应该确保在向图表添加额外的控制结构时，定期使用`helm template`渲染您的模板，因为这些控制结构可能会使图表开发过程变得更加困难，特别是如果控制结构数量众多或复杂。

除了检查控制结构是否正确生成外，您还应检查您的函数和流水线是否按预期工作，接下来我们将讨论这一点。

### 测试函数和流水线

`helm template`命令还可以用于验证函数和流水线生成的渲染结果，这些函数和流水线通常用于生成格式化的 YAML。

以以下模板为例：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
          resources:
{{ .Values.resources | toYaml | indent 12 }}
```

此模板包含一个流水线，该流水线对`resources`值进行参数化和格式化，以指定容器的资源需求。在您的图表的`values.yaml`文件中包含一个明智的默认值，以确保应用程序具有适当的限制，以防止集群资源的过度利用。

此模板的`resources`值示例如下：

```
resources:
  limits:
    cpu: 200m
    memory: 256Mi
```

您需要运行`helm template`命令，以确保该值被正确转换为有效的`YAML`格式，并且输出被正确缩进以生成有效的部署资源。

对此模板运行`helm template`命令的结果如下：

```
apiVersion: apps/v1
kind: Deployment
<skipping>
          resources:
            limits:
              cpu: 200m
              memory: 256Mi
```

接下来，我们将讨论如何在使用`helm template`渲染资源时启用服务器端验证。

向图表渲染添加服务器端验证

虽然`helm template`命令对图表开发过程很重要，并且应该经常用于验证图表渲染，但它确实有一个关键的限制。`helm template`命令的主要目的是提供客户端渲染，这意味着它不会与 Kubernetes API 服务器通信以提供资源验证。如果您希望在生成资源后确保资源有效，可以使用`--validate`标志指示`helm template`在生成资源后与 Kubernetes API 服务器通信：

```
$ helm template my-chart $CHART_DIRECTORY --validate
```

任何生成的模板如果未生成有效的 Kubernetes 资源，则会提供错误消息。例如，假设使用了一个部署模板，其中`apiVersion`值设置为`apiVersion: v1`。为了生成有效的部署，必须将`apiVersion`值设置为`apps/v1`，因为这是提供部署资源的 API 的正确名称。仅将其设置为`v1`将通过`helm template`的客户端渲染生成看似有效的资源，但是使用`--validation`标志，您期望看到以下错误：

```
Error: unable to build kubernetes objects from release manifest: unable to recognize '': no matches for kind 'Deployment' in version 'v1'
```

`--validate`标志旨在捕获生成的资源中的错误。如果您可以访问 Kubernetes 集群，并且想要确定您的图表是否生成有效的 Kubernetes 资源，则应使用此标志。或者，您可以针对`install`、`upgrade`、`rollback`和`uninstall`命令使用`--dry-run`标志来执行验证。

以下是使用此标志与`install`命令的示例：

```
$ helm install my-chart $CHART --dry-run
```

此标志将生成图表的模板并执行验证，类似于使用`--validate`标志运行`helm template`命令。使用`--dry-run`将在命令行打印每个生成的资源，并且不会在 Kubernetes 环境中创建资源。它主要由最终用户使用，在运行安装之前执行健全性检查，以确保他们提供了正确的值，并且安装将产生期望的结果。图表开发人员可以选择以这种方式使用`--dry-run`标志来测试图表渲染和验证，或者他们可以选择使用`helm template`在本地生成图表的资源，并提供`--validate`以添加额外的服务器端验证。

虽然有必要验证您的模板是否按照您的意图生成，但也有必要确保您的模板是按照最佳实践生成的，以简化开发和维护。Helm 提供了一个名为`helm lint`的命令，可以用于此目的，我们将在下面更多地了解它。

## Linting Helm charts and templates

对您的图表进行 lint 是很重要的，可以防止图表格式或图表定义文件中的错误，并在使用 Helm 图表时提供最佳实践的指导。`helm lint`命令具有以下语法：

```
$ helm lint PATH [flags]
```

`helm lint`命令旨在针对图表目录运行，以确保图表是有效的和正确格式化的。

重要提示：

`helm lint`命令不验证渲染的 API 模式，也不对您的 YAML 样式进行 linting，而只是检查图表是否包含应有的文件和设置，这是一个有效的 Helm 图表应该具有的。

您可以对您在*第五章*中创建的 Guestbook 图表，或者对 Packt GitHub 存储库中`helm-charts/charts/guestbook`文件夹下的图表运行`helm lint`命令，网址为[`github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/charts/guestbook`](https://github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/charts/guestbook)：

```
$ helm lint $GUESTBOOK_CHART_PATH
==> Linting guestbook/
[INFO] Chart.yaml: icon is recommended
1 chart(s) linted, 0 chart(s) failed
```

这个输出声明了图表是有效的，这是由`1 chart(s) linted, 0 chart(s) failed`消息所指出的。`[INFO]`消息建议图表在`Chart.yaml`文件中包含一个`icon`字段，但这并非必需。其他类型的消息包括`[WARNING]`，它表示图表违反了图表约定，以及`[ERROR]`，它表示图表将在安装时失败。

让我们通过一些例子来运行。考虑一个具有以下文件结构的图表：

```
guestbook/
  templates/
  values.yaml
```

请注意，这个图表结构存在问题。这个图表缺少定义图表元数据的`Chart.yaml`文件。对具有这种结构的图表运行 linter 会产生以下错误：

```
==> Linting .
Error unable to check Chart.yaml file in chart: stat Chart.yaml: no such file or directory
Error: 1 chart(s) linted, 1 chart(s) failed
```

这个错误表明 Helm 找不到`Chart.yaml`文件。如果向图表中添加一个空的`Chart.yaml`文件以提供正确的文件结构，错误仍会发生，因为`Chart.yaml`文件包含无效的内容：

```
guestbook/
  Chart.yaml  # Empty
  templates/
  values.yaml
```

对这个图表运行 linter 会产生以下错误：

```
==> Linting .
[ERROR] Chart.yaml: name is required
[ERROR] Chart.yaml: apiVersion is required. The value must be either 'v1' or 'v2'
[ERROR] Chart.yaml: version is required
[INFO] Chart.yaml: icon is recommended
[ERROR] templates/: validation: chart.metadata.name is required
Error: 1 chart(s) linted, 1 chart(s) failed
```

此输出列出了在`Chart.yaml`文件中缺少的必需字段。它指示该文件必须包含`name`、`apiVersion`和`version`字段，因此应将这些字段添加到`Chart.yaml`文件中以生成有效的 Helm 图表。检查器还对`apiVersion`和`version`设置提供了额外的反馈，检查`apiVersion`值是否设置为`v1`或`v2`，以及`version`设置是否为正确的`SemVer`版本。

该检查器还将检查其他必需或建议的文件的存在，例如`values.yaml`文件和`templates`目录。它还将确保`templates`目录下的文件具有`.yaml`、`.yml`、`.tpl`或`.txt`文件扩展名。`helm lint`命令非常适合检查图表是否包含适当的内容，但它不会对图表的 YAML 样式进行广泛的 linting。

要执行此 linting，您可以使用另一个名为`yamllint`的工具，该工具可以在[`github.com/adrienverge/yamllint`](https://github.com/adrienverge/yamllint)找到。可以使用以下命令在一系列操作系统上使用`pip`软件包管理器安装此工具：

```
pip install yamllint --user
```

也可以按照`yamllint`快速入门说明中描述的方式，使用操作系统的软件包管理器进行安装，该说明位于[`yamllint.readthedocs.io/en/stable/quickstart.html`](https://yamllint.readthedocs.io/en/stable/quickstart.html)。

为了在图表的 YAML 资源上使用`yamllint`，您必须将其与`helm template`命令结合使用，以去除 Go 模板化并生成您的 YAML 资源。

以下是针对 Packt GitHub 存储库中的 guestbook 图表运行此命令的示例：

```
$ helm template my-guestbook Learn-Helm/helm-charts/charts/guestbook | yamllint -
```

此命令将在`templates/`文件夹下生成资源，并将输出传输到`yamllint`。

结果如下所示：

![图 6.2 - 一个示例 yamllint 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.2.jpg)

图 6.2 - 一个示例`yamllint`输出

提供的行号反映了整个`helm template`输出，这可能会使确定`yamllint`输出中的哪一行对应于您的 YAML 资源中的哪一行变得困难。

您可以通过将`helm template`输出重定向到以下命令来确定其行号，针对`guestbook`图表：

```
$ cat -n <(helm template my-guestbook Learn-Helm/helm-charts/charts/guestbook)
```

`yamllint`将针对许多不同的规则进行 lint，包括以下内容：

+   缩进

+   行长度

+   训练空间

+   空行

+   注释格式

您可以通过创建以下文件之一来覆盖默认规则：

+   `.yamllint`、`.yamllint.yaml`和`.yamllint.yml`在当前工作目录中

+   `$XDB_CONFIG_HOME/yamllint/config`

+   `~/.config/yamllint/config`

要覆盖针对 guestbook 图表报告的缩进规则，您可以在当前工作目录中创建一个`.yamllint.yaml`文件，其中包含以下内容：

```
rules:
  indentation:
    # Allow      myList
    #            - item1
    #            - item2
    # Or
    #            myList
    #              - item1
    #              - item2
    indent-sequences: whatever
```

此配置覆盖了`yamllint`，使其在添加列表条目时不强制执行一种特定的缩进方法。它由`indent-sequences: whatever`行配置。创建此文件并再次针对 guestbook 运行 linter 将消除先前看到的缩进错误：

```
$ helm template my-guestbook guestbook | yamllint -
```

在本节中，我们讨论了如何使用`helm template`和`helm lint`命令验证 Helm 图表的本地渲染。然而，这实际上并没有测试您的图表功能或应用程序使用您的图表创建的资源的能力。

在下一节中，我们将学习如何在实时 Kubernetes 环境中创建测试来测试您的 Helm 图表。

# 在实时集群中进行测试

创建图表测试是开发和维护 Helm 图表的重要部分。图表测试有助于验证您的图表是否按预期运行，并且它们可以帮助防止在添加功能和修复图表时出现回归。

测试包括两个不同的步骤。首先，您需要在图表的`templates/`目录下创建包含`helm.sh/hook`: test`注释的`pod`模板。这些`pod`将运行测试您的图表和应用程序功能的命令。接下来，您需要运行`helm test`命令，该命令会启动`test`钩子并创建具有上述注释的资源。

在本节中，我们将学习如何通过向 Guestbook 图表添加测试来在实时集群中进行测试，继续开发您在上一章中创建的图表。作为参考，您将创建的测试可以在 Packt 存储库中的 Guestbook 图表中查看，位于[`github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/charts/guestbook`](https://github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/charts/guestbook)。

从您的 Guestbook 图表的`templates/`目录下添加`test/frontend-connection.yaml`和`test/redis-connection.yaml`文件开始。请注意，图表测试不一定要位于`test`子目录下，但将它们放在那里是一种很好的方式，可以使您的测试组织和主要图表模板分开：

```
$ mkdir $GUESTBOOK_CHART_DIR/templates/test
$ touch $GUESTBOOK_CHART_DIR/templates/test/frontend-connection.yaml
$ touch $GUESTBOOK_CHART_DIR/templates/test/backend-connection.yaml
```

在本节中，我们将填充这些文件以验证它们关联的应用程序组件的逻辑。

现在我们已经添加了占位符，让我们开始编写测试。

## 创建图表测试

您可能还记得，Guestbook 图表由 Redis 后端和 PHP 前端组成。用户在前端的对话框中输入消息，并且这些消息将持久保存到后端。让我们编写一些测试，以确保安装后前端和后端资源都可用。我们将从检查 Redis 后端的可用性开始。将以下内容添加到图表的`templates/test/backend-connection.yaml`文件中（此文件也可以在 Packt 存储库中查看：https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/templates/test/backend-connection.yaml）：

![图 6.3 - 对 Guestbook 服务的 HTTP 请求](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.3.jpg)

图 6.3 - Guestbook Helm 图表的后端连接测试

此模板定义了在测试生命周期钩子期间将创建的 Pod。此模板中还定义了一个钩子删除策略，指示何时应删除先前的测试 Pod。如果我们创建的测试需要按顺序运行，还可以添加钩子权重。

容器对象下的 args 字段显示了测试将基于的命令。它将使用 redis-cli 工具连接到 Redis 主服务器并运行命令 MGET messages。Guestbook 前端设计为将用户输入的消息添加到名为 messages 的数据库键中。这个简单的测试旨在检查是否可以连接到 Redis 数据库，并且它将通过查询 messages 键返回用户输入的消息。

PHP 前端也应该进行可用性测试，因为它是应用程序的用户界面组件。将以下内容添加到 templates/test/frontend-connection.yaml 文件中（这些内容也可以在 Packt 存储库 https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/templates/test/frontend-connection.yaml 中找到）。

![图 6.4 - Guestbook Helm 图表的前端连接测试](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.4-1.jpg)

图 6.4 - Guestbook Helm 图表的前端连接测试

这是一个非常简单的测试，它会向 Guestbook 服务发送 HTTP 请求。发送到服务的流量将在 Guestbook 前端实例之间进行负载平衡。此测试将检查负载平衡是否成功执行以及前端是否可用。

现在，我们已经完成了图表测试所需的模板。请注意，这些模板也可以通过 helm 模板命令在本地呈现，并使用 helm lint 和 yamllint 进行检查，如本章前面部分所述。在开发自己的 Helm 图表时，您可能会发现这对于更高级的测试用例很有用。

现在测试已经编写完成，我们将继续在 Minikube 环境中运行它们。

## 运行图表测试

为了运行图表的测试，必须首先使用`helm install`命令在 Kubernetes 环境中安装图表。因为编写的测试是设计在安装完成后运行的，所以可以在安装图表时使用`--wait`标志，以便更容易确定何时 pod 准备就绪。运行以下命令安装 Guestbook 图表：

```
$ helm install my-guestbook $GUESTBOOK_CHART_DIR -n chapter6 --wait
```

安装图表后，可以使用`helm test`命令执行`test`生命周期钩子并创建测试资源。`helm test`命令的语法如下所示：

```
helm test [RELEASE] [flags]
```

针对`my-guestbook`发布运行`helm test`命令：

```
$ helm test my-guestbook -n chapter6
```

如果您的测试成功，您将在输出中看到以下结果：

```
TEST SUITE:     my-guestbook-test-frontend-connection
Last Started:   Tue Jan 28 18:50:23 2020
Last Completed: Tue Jan 28 18:50:25 2020
Phase:          Succeeded
TEST SUITE:     my-guestbook-test-backend-connection
Last Started:   Tue Jan 28 18:50:25 2020
Last Completed: Tue Jan 28 18:50:26 2020
Phase:          Succeeded
```

在运行测试时，还可以使用`--logs`标志将日志打印到命令行，从而执行测试。

使用此标志再次运行测试：

```
$ helm test my-guestbook -n chapter6 --logs
```

您将看到与之前相同的测试摘要，以及每个测试相关的容器日志。以下是前端连接测试日志输出的第一部分：

```
POD LOGS: my-guestbook-test-frontend-connection
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
<html ng-app='redis'>
  <head>
    <title>Guestbook</title>
```

以下是后端连接`test`日志输出：

```
POD LOGS: my-guestbook-test-backend-connection
```

这次测试的日志将为空，因为您尚未在 Guestbook 前端输入任何消息。您可以在从前端添加消息后再次运行测试，以确保消息持久。在运行安装和`test`套件时，会打印确定 Guestbook 前端 URL 的说明。

这些说明再次显示在这里：

```
export IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}')
export PORT=$(kubectl get svc my-guestbook -n chapter6 -o jsonpath='{.spec.ports[0].nodePort}')
echo http://$IP:$PORT
```

从浏览器访问前端后，向 Guestbook 应用程序添加一条消息。

以下是一个示例截图：

![图 6.4 - Guestbook 应用程序的前端](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.4.jpg)

图 6.4-1 - Guestbook 应用程序的前端

一旦添加了消息，再次运行`test`套件，使用`--logs`标志显示测试日志。您应该能够通过观察后端连接`test`日志输出来验证是否已添加此消息：

```
$ helm test my-guestbook -n chapter6 --logs
```

以下是显示后端连接`test`日志输出的片段。您可以验证消息是否已持久到 Redis 数据库中：

```
POD LOGS: my-guestbook-test-backend-connection
,Writing Helm charts is fun!
```

在本节中，我们编写了简单的测试，作为一个整体，对图表的安装进行了烟雾测试。有了这些测试，我们将更有信心对图表进行更改和添加功能，前提是在每次修改后运行图表测试以确保功能保持不变。

在下一节中，我们将讨论如何通过利用一个名为`ct`的工具来改进测试过程。

# 使用图表测试项目改进图表测试

前一节中编写的测试已足够测试 Guestbook 应用程序是否可以成功安装。然而，标准 Helm 测试过程中存在一些关键限制，需要指出。

要考虑的第一个限制是测试图表值中可能发生的不同排列的困难。因为`helm test`命令无法修改您发布的值，除了在安装或升级时设置的值，所以在针对不同的值设置运行`helm test`时，必须遵循以下工作流程：

1.  使用初始值安装您的图表。

1.  针对您的发布运行`helm test`。

1.  删除您的发布。

1.  使用不同的值集安装您的图表。

1.  重复*步骤 2*到*4*，直到测试了大量的值可能性。

除了测试不同值的排列组合外，您还应确保在修改图表时不会出现回归。防止回归并测试图表的新版本的最佳方法是使用以下工作流程：

1.  安装先前的图表版本。

1.  将您的发布升级到更新的图表版本。

1.  删除发布。

1.  安装更新的图表版本。

对每组值的排列组合重复此工作流程，以确保没有回归或意外的破坏性更改发生。

这些流程听起来很繁琐，但想象一下当维护多个不同的 Helm 图表时，图表开发人员需要进行仔细的测试，会增加额外的压力和维护工作。在维护多个 Helm 图表时，图表开发人员倾向于采用`git` monorepo 设计。当同一个存储库中包含多个不同的构件或模块时，该存储库被认为是 monorepo。

在 Helm 图表的情况下，monorepo 可能具有以下文件结构：

```
helm-charts/
  guestbook/
    Chart.yaml
    templates/
    README.md
    values.yaml
  redis/           # Contains the same file structure as 'guestbook'
  wordpress/       # Contains the same file structure as 'guestbook'
  README.md
```

在修改 Helm 图表时，应对其进行测试，以确保没有意外的破坏性更改发生。当修改图表时，其`Chart.yaml`文件中的`version`字段也应根据正确的`SemVer`版本进行增加，以表示所做更改的类型。`SemVer`版本遵循`MAJOR.MINOR.PATCH`版本编号格式。

使用以下列表作为如何增加`SemVer`版本的指南：

+   如果您对图表进行了破坏性更改，请增加`MAJOR`版本。破坏性更改是指与先前的图表版本不兼容的更改。

+   如果您正在添加一个功能但没有进行破坏性更改，请增加`MINOR`版本。如果您所做的更改与先前的图表版本兼容，应该增加此版本。

+   如果您正在修复错误或安全漏洞，而不会导致破坏性更改，请增加`PATCH`版本。如果更改与先前的图表版本兼容，应该增加此版本。

没有良好编写的自动化，当修改图表并增加它们的版本时，确保测试图表会变得越来越困难，特别是在维护多个 Helm 图表的 monorepo 时。这一挑战促使 Helm 社区创建了一个名为`ct`的工具，以提供图表测试和维护的结构和自动化。我们接下来将讨论这个工具。

## 介绍图表测试项目

图表测试项目可以在[`github.com/helm/chart-testing`](https://github.com/helm/chart-testing)找到，并设计用于针对 git monorepo 中的图表执行自动化的 linting、验证和测试。通过使用 git 检测已更改的图表来实现自动化测试。已更改的图表应该经历测试过程，而未更改的图表则无需进行测试。

该项目的 CLI`ct`提供了四个主要命令：

+   `lint`：对已修改的图表进行 lint 和验证

+   `install`：安装和测试已修改的图表

+   `lint-and-install`：对已修改的图表进行 lint、安装和测试

+   `list-changed`：列出已修改的图表

`list-changed`命令不执行任何验证或测试，而`lint-and-install`命令将`lint`和`install`命令结合起来，对已修改的图表进行`lint`、`install`和`test`。它还会检查您是否已增加了每个图表的`Chart.yaml`文件中修改的图表的`version`字段，并对未增加版本但内容已修改的图表进行测试失败。这种验证有助于维护者根据所做更改的类型保持严格，以增加其图表版本。

除了检查图表版本外，图表测试还提供了为测试目的指定多个值文件的能力。在调用`lint`、`install`和`lint-and-install`命令时，图表测试会循环遍历每个测试`values`文件，以覆盖图表的默认值，并根据提供的不同值排列进行验证和测试。测试`values`文件写在一个名为`ci/`的文件夹下，以将这些值与图表的默认`values.yaml`文件分开，如下例文件结构所示：

```
guestbook/
  Chart.yaml
  ci/
    nodeport-service-values.yaml
    ingress-values.yaml
  templates/
  values.yaml
```

图表测试适用于`ci/`文件夹下的每个`values`文件，无论文件使用的名称如何。您可能会发现，根据被覆盖的值为每个`values`文件命名，以便维护者和贡献者可以理解文件内容，这是有帮助的。

您可能会经常使用的最常见的`ct`命令是`lint-and-install`命令。以下列出了该命令用于 lint、安装和测试在`git` monorepo 中修改的图表的步骤：

1.  检测已修改的图表。

1.  使用`helm repo update`命令更新本地 Helm 缓存。

1.  使用`helm dependency build`命令下载每个修改后的图表的依赖项。

1.  检查每个修改后的图表版本是否已递增。

1.  对于在*步骤 4*中评估为`true`的每个图表，对图表和`ci/`文件夹下的每个`values`文件进行 lint。

1.  对于在*步骤 4*中评估为`true`的每个图表，执行以下附加步骤：

在自动创建的命名空间中安装图表。

通过执行`helm test`来运行测试。

删除命名空间。

在`ci/`文件夹下的每个`values`文件上重复。

正如您所看到的，该命令执行各种不同的步骤，以确保您的图表通过在单独的命名空间中安装和测试每个修改后的图表来正确进行 lint 和测试，重复该过程对`ci/`文件夹下定义的每个`values`文件。然而，默认情况下，`lint-and-install`命令不会通过从图表的旧版本升级来检查向后兼容性。可以通过添加`--upgrade`标志来启用此功能：

如果没有指示有破坏性变化，则`--upgrade`标志会修改*上一组步骤*中的*步骤 6*，通过运行以下步骤：

1.  在自动创建的命名空间中安装图表的旧版本。

1.  通过执行`helm test`来运行测试。

1.  升级发布到修改后的图表版本并再次运行测试。

1.  删除命名空间。

1.  在新的自动创建的命名空间中安装修改后的图表版本。

1.  通过执行`helm test`来运行测试。

1.  再次使用相同的图表版本升级发布并重新运行测试。

1.  删除命名空间。

1.  在`ci/`文件夹下的每个`values`文件上重复。

建议您添加`--upgrade`标志，以便对 Helm 升级进行额外测试，并防止可能的回归。

重要提示：

`--upgrade`标志将不会生效，如果您已经增加了 Helm 图表的`MAJOR`版本，因为这表示您进行了破坏性更改，并且在此版本上进行就地升级将不会成功。

让我们在本地安装图表测试 CLI 及其依赖项，以便稍后可以看到此过程的实际操作。

## 安装图表测试工具

为了使用图表测试 CLI，您必须在本地机器上安装以下工具：

+   `helm`

+   `git`（版本`2.17.0`或更高）

+   `yamllint`

+   `yamale`

+   `kubectl`

图表测试在测试过程中使用这些工具。`helm`和`kubectl`在*第二章*中安装，*准备 Kubernetes 和 Helm 环境*，Git 在*第五章*中安装，*构建您的第一个 Helm 图表*，yamllint 在本章开头安装。如果您迄今为止一直在跟随本书，现在您应该需要安装的唯一先决条件工具是 Yamale，这是图表测试用来验证您的图表的`Chart.yaml`文件与`Chart.yaml`模式文件相匹配的工具。

Yamale 可以使用`pip`软件包管理器安装，如下所示：

```
$ pip install yamale --user
```

您也可以通过从[`github.com/23andMe/Yamale/archive/master.zip`](https://github.com/23andMe/Yamale/archive/master.zip)手动下载存档来安装 Yamale。

下载后，解压缩存档并运行安装脚本：

```
$ python setup.py install
```

请注意，如果您使用下载的存档安装工具，您可能需要以提升的权限运行`setup.py`脚本，例如在 macOS 和 Linux 上作为管理员或 root 用户。

安装所需的工具后，您应该从项目的 GitHub 发布页面[`github.com/helm/chart-testing/releases`](https://github.com/helm/chart-testing/releases)下载图表测试工具。每个发布版本都包含一个*Assets*部分，其中列出了存档文件。

下载与本地机器平台类型对应的存档。本书使用的版本是`v3.0.0-beta.1`：

![图 6.5 - GitHub 上的图表测试发布页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.5.jpg)

图 6.5 - GitHub 上的图表测试发布页面

从 GitHub 发布页面下载适当的文件后，解压缩图表测试版本。解压缩后，您将看到以下内容：

```
LICENSE
README.md
etc/chart_schema.yaml
etc/lintconf.yaml
ct
```

您可以删除`LICENSE`和`README.md`文件，因为它们是不需要的。

`etc/chart_schema.yaml`和`etc/lintconf.yaml`文件应移动到本地计算机上的`$HOME/.ct/`或`/etc/ct/`位置。`ct`文件应移动到由系统的`PATH`变量管理的位置：

```
$ mkdir $HOME/.ct
$ mv $HOME/Downloads/etc/* $HOME/.ct/
$ mv $HOME/Downloads/ct /usr/local/bin/
```

现在，所有必需的工具都已安装。在本示例中，我们将在本地对 Packt 存储库进行更改，并使用图表测试来对修改后的图表进行 lint 和安装。

如果您尚未将存储库克隆到本地计算机，请立即执行此操作：

```
$ git clone https://github.com/PacktPublishing/-Learn-Helm Learn-Helm
```

克隆后，您可能会注意到该存储库在顶层有一个名为`ct.yaml`的文件，其中包含以下内容：

```
chart-dirs:
  - helm-charts/charts
chart-repos:
  - bitnami=https://charts.bitnami.com
```

该文件的`chart-dirs`字段指示`ct`，相对于`ct.yaml`文件，`helm-charts/charts`目录是图表 monorepo 的根目录。`chart-repos`字段提供了应该运行`helm repo add`的存储库列表，以确保它能够下载依赖项。

还有许多其他配置可以添加到此文件中，这些将在此时不予讨论，但可以在图表测试文档中查看。每次调用`ct`命令都会引用`ct.yaml`文件。

现在，工具已安装，并且 Packt 存储库已克隆，让我们通过执行`lint-and-install`命令来测试`ct`工具。

运行图表测试 lint-and-install 命令

`lint-and-install`命令针对`Learn-Helm/helm-charts/charts`下包含的三个 Helm 图表使用：

+   `guestbook`：这是您在上一章中编写的 Guestbook 图表。

+   `nginx`：这是我们为演示目的包含的另一个 Helm 图表。通过运行`helm create`命令创建的此图表用于部署`nginx`反向代理。

要运行测试，首先导航到`Learn-Helm`存储库的顶层：

```
$ cd $LEARN_HELM_LOCATION
$ ls
ct.yaml  guestbook-operator  helm-charts  jenkins  LICENSE  nginx-cd  README.md
```

`ct.yaml`文件通过`chart-dirs`字段显示了图表 monorepo 的位置，因此您可以直接从顶层运行`ct lint-and-install`命令：

```
$ ct lint-and-install
```

运行此命令后，您将在输出的末尾看到以下消息显示：

![图 6.6 - 当图表没有被修改时的图表测试 lint-and-install 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.6.jpg)

图 6.6 - 当图表没有被修改时的图表测试`lint-and-install`输出

由于这个存储库中的图表都没有被修改，`ct`没有对您的图表执行任何操作。我们应该至少修改其中一个图表，以便看到`lint-and-install`过程发生。修改应该发生在`master`之外的分支上，因此应该通过执行以下命令创建一个名为`chart-testing-example`的新分支：

```
$ git checkout -b chart-testing-example
```

修改可以是大的或小的；对于这个例子，我们将简单地修改每个图表的`Chart.yaml`文件。修改`Learn-Helm/helm-charts/charts/guestbook/Chart.yaml`文件的`description`字段如下所示：

```
description: Used to deploy the Guestbook application
```

先前，这个值是`A Helm chart for Kubernetes`。

修改`Learn-Helm/helm-charts/charts/nginx/Chart.yaml`文件的`description`字段如下所示：

```
description: Deploys an NGINX instance to Kubernetes
```

先前，这个值是`A Helm chart for Kubernetes`。通过运行`git status`命令验证上次`git`提交后两个图表是否已被修改：

![图 6.7 - 在修改了两个图表后的 git status 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.7.jpg)

图 6.7 - 在修改了两个图表后的`git status`输出

您应该看到`guestbook`和`nginx`图表的变化。修改了这些图表后，尝试再次运行`lint-and-install`命令：

```
$ ct lint-and-install
```

这次，`ct`确定了这个 monorepo 中两个图表是否发生了更改，如下所示的输出：

![图 6.8 - 指示对 guestbook 和 nginx 图表的更改的消息](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.8.jpg)

图 6.8 - 指示对`guestbook`和`nginx`图表的更改的消息

然而，这个过程后来会失败，因为这两个图表的版本都没有被修改：

![图 6.9 - 当没有图表更改时的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_6.9.jpg)

图 6.9 - 当没有图表更改时的输出

这可以通过增加`guestbook`和`nginx`图表的版本来解决。由于这个更改没有引入新功能，我们将增加`PATCH`版本。在各自的`Chart.yaml`文件中将两个图表的版本都修改为`version 1.0.1`：

```
version: 1.1.0
```

通过运行`git diff`命令确保每个图表都已进行了此更改。如果在输出中看到每个版本的修改，请继续再次运行`lint-and-install`命令：

```
$ ct lint-and-install
```

现在图表版本已经增加，`lint-and-install`命令将遵循完整的图表测试工作流程。您将看到每个修改的图表都会被 linted 并部署到自动创建的命名空间中。一旦部署的应用程序的 pod 被报告为就绪状态，`ct`将自动运行每个图表的测试用例，这些测试用例由带有`helm.sh/hook: test`注释的资源表示。图表测试还将打印每个测试 pod 的日志，以及命名空间事件。

您可能会注意到，在`lint-and-install`输出中，`nginx`图表部署了两次，而`guestbook`图表只部署和测试了一次。这是因为`nginx`图表有一个位于`Learn-Helm/helm-charts/charts/nginx/ci/`的`ci/`文件夹，其中包含两个不同的`values`文件。`ci/`文件夹中的`values`文件将被图表测试迭代，该测试将安装与`values`文件数量相同的图表，以确保每个值组合都能成功安装。`guestbook`图表不包括`ci/`文件夹，因此此图表只安装了一次。

这可以在`lint-and-install`输出的以下行中观察到：

```
Linting chart with values file 'nginx/ci/clusterip-values.yaml'...
Linting chart with values file 'nginx/ci/nodeport-values.yaml'...
Installing chart with values file 'nginx/ci/clusterip-values.yaml'...
Installing chart with values file 'nginx/ci/nodeport-values.yaml'...
```

虽然该命令对于测试两个图表的功能很有用，但它并未验证对新版本的升级是否成功。

为此，我们需要向`lint-and-install`命令提供`--upgrade`标志。再次尝试运行此命令，但这次使用`--upgrade`标志：

```
$ ct lint-and-install --upgrade
```

这次，每个`ci/`下的`values`文件将进行原地升级。这可以在输出中看到如下：

```
Testing upgrades of chart 'guestbook => (version: '1.0.1', path: 'guestbook')' relative to previous revision 'guestbook => (version: '1.0.0', path: 'ct_previous_revision216728160/guestbook')'...
```

请记住，只有在版本之间的`MAJOR`版本相同时，原地升级才会被测试。如果您使用`--upgrade`标志，但未更改`MAJOR`版本，您将看到类似以下的消息：

```
Skipping upgrade test of 'guestbook => (version: '2.0.0', path: 'helm-charts/charts/guestbook')' because: 1 error occurred:
	* 2.0.0 does not have same major version as 1.0.0
```

现在，通过了解如何使用图表测试对 Helm 图表进行强大的测试，我们将通过清理您的`minikube`环境来结束。

# 清理

如果您已经完成了本章中描述的示例，可以从您的`minikube`集群中删除`chapter6`命名空间：

```
$ kubectl delete ns chapter6
```

最后，通过运行`minikube stop`关闭您的`minikube`集群。

# 摘要

在本章中，您了解了可以应用于测试 Helm 图表的不同方法。测试图表的最基本方法是针对本地图表目录运行`helm template`命令，以确定其资源是否正确生成。您还可以使用`helm lint`命令来确保您的图表遵循正确的格式，并且可以使用`yamllint`命令来检查图表中使用的 YAML 样式。

除了本地模板化和检查外，您还可以使用`helm test`命令和`ct`工具在 Kubernetes 环境中执行实时测试。除了执行图表测试外，图表测试还提供了使图表开发人员更容易在 monorepo 中维护 Helm 图表的功能。

在下一章中，您将了解 Helm 如何在**持续集成/持续交付**（**CI/CD**）和 GitOps 设置中使用，从图表开发人员构建和测试 Helm 图表的角度，以及从使用 Helm 将应用程序部署到 Kubernetes 的最终用户的角度。

# 进一步阅读

有关`helm template`和`helm lint`命令的更多信息，请参阅以下资源：[`helm.sh/docs/helm/helm_template/`](https://helm.sh/docs/helm/helm_template/)

+   `helm template`：[`helm.sh/docs/helm/helm_template/`](https://helm.sh/docs/helm/helm_template/)

+   `helm lint`：[`helm.sh/docs/helm/helm_lint/`](https://helm.sh/docs/helm/helm_lint/)

Helm 文档中的以下页面讨论了图表测试和`helm test`命令：[`helm.sh/docs/topics/chart_tests/`](https://helm.sh/docs/topics/chart_tests/)

+   图表测试：[`helm.sh/docs/topics/chart_tests/`](https://helm.sh/docs/topics/chart_tests/)

+   `helm test`命令：[`helm.sh/docs/helm/helm_test/`](https://helm.sh/docs/helm/helm_test/)

+   最后，请查看有关`ct` CLI 的图表测试 GitHub 存储库的更多信息：[`github.com/helm/chart-testing`](https://github.com/helm/chart-testing)。

# 问题

1.  `helm template`命令的目的是什么？它与`helm lint`命令有何不同？

1.  在将图表模板安装到 Kubernetes 之前，您可以做什么来验证它们？

1.  可以利用哪个工具来检查您的 YAML 资源的样式？

1.  如何创建图表测试？如何执行图表测试？

1.  `ct`工具为 Helm 内置的测试功能带来了什么附加价值？

1.  在使用`ct`工具时，`ci/`文件夹的目的是什么？

1.  `--upgrade` 标志如何改变 `ct lint-and-install` 命令的行为？


# 第三部分：高级部署模式

本节将在基本概念的基础上进行构建，并将教你更多关于使用 Helm 进行应用管理的高级概念和可能性。

本节包括以下章节：

第七章，使用 CI/CD 和 GitOps 自动化 Helm 流程

第八章，使用 Operator Framework 与 Helm

第九章，Helm 安全考虑


# 第七章：使用 CI/CD 和 GitOps 自动化 Helm 流程

在本书中，我们迄今为止讨论了两个高级流程。首先，我们探讨了使用 Helm 作为最终用户，利用 Helm 作为软件包管理器将各种复杂性的应用程序部署到 Kubernetes。其次，我们探讨了作为图表开发人员开发和测试 Helm 图表，这涉及将 Kubernetes 的复杂性封装在 Helm 图表中，并对图表进行测试，以确保所需的功能成功交付给最终用户。

这两个流程都涉及调用各种不同的 Helm CLI 命令。这些 Helm CLI 命令在执行各自的任务时非常有效，但需要从命令行手动调用。手动调用在管理多个不同的图表或应用程序时可能会成为一个痛点，并且可能会使大型企业难以扩展。因此，我们应该探索提供额外自动化的替代选项，以在 Helm 已经提供的基础上提供额外的自动化。在本章中，我们将调查与**持续集成**和**持续交付**（**CI**/**CD**）以及`GitOps`相关的概念，这些方法可以自动调用 Helm CLI 以及其他命令，以执行针对 Git 存储库的自动化工作流。这些工作流可以用于使用 Helm 自动部署应用程序，并在图表开发生命周期中构建、测试和打包 Helm 图表。

在本章中，我们将涵盖以下主题：

+   理解 CI/CD 和 GitOps

+   设置我们的环境

+   创建用于构建 Helm 图表的 CI 流水线

+   使用 Helm 创建 CD 流水线以部署应用程序

+   清理

# 技术要求

本章需要您在本地机器上安装以下技术：

+   Minikube

+   Helm

+   kubectl

+   Git

除了这些工具，您还应该在 GitHub 的 Packt 存储库中找到与本章中使用的示例相关的资源，网址为[`github.com/PacktPublishing/-Learn-Helm`](https://github.com/PacktPublishing/-Learn-Helm)。本存储库将在本章中被引用。

# 理解 CI/CD 和 GitOps

到目前为止，我们已经讨论了许多与 Helm 开发相关的关键概念——构建、测试和部署。然而，我们的探索仅限于手动配置和调用 Helm CLI。当您希望将图表移入类似生产环境时，有几个问题需要考虑，包括以下内容：

+   我如何确保图表开发和部署的最佳实践得到执行？

+   合作者参与开发和部署过程的影响是什么？

这些观点适用于任何软件项目，不仅适用于 Helm 图表开发。虽然我们已经涵盖了许多最佳实践，但在接纳新的合作者时，他们可能对这些主题没有相同的理解，或者没有执行这些关键步骤的纪律。通过使用自动化和可重复的流程，诸如 CI/CD 之类的概念已经被建立起来，以解决其中的一些挑战。

## CI/CD

需要一个自动化的软件开发流程，每次软件发生变化时都能遵循，这导致了 CI 的产生。CI 不仅确保了最佳实践的遵守，而且还有助于消除许多开发人员面临的常见挑战，正如“它在我的机器上可以运行”所体现的。我们之前讨论过的一个因素是使用版本控制系统，比如`git`，来存储源代码。通常，每个用户都会有自己独立的源代码副本，这使得在增加贡献者时难以管理代码库。

CI 是通过使用自动化工具来正确启用的，其中源代码在发生更改时经历一组预定的步骤。对于正确的自动化工具的需求导致了专门为此目的设计的软件的兴起。一些 CI 工具的例子包括 Jenkins、TeamCity 和 Bamboo，以及各种基于软件即服务（SaaS）的解决方案。通过将任务的责任转移到第三方组件，开发人员更有可能频繁提交代码，项目经理可以对团队的技能和产品的健壮性感到自信。

大多数这些工具中都具有的一个关键特性是能够及时通知项目当前状态的能力。通过使用持续集成，不是在软件开发周期的后期才发现破坏性变化，而是在变化被整合后立即执行流程并向相关方发送通知。通过利用快速通知，它为引入变化的用户提供了解决问题的机会，而兴趣所在的领域正处于头脑前沿，而不是在交付过程的后期，当时他们可能已经在其他地方忙碌。

将 CI 的许多概念应用于整个软件交付生命周期，随着应用程序向生产环境推进，导致了 CD 的产生。CD 是一组定义的步骤，编写用于推进软件通过发布过程（更常被称为流水线）。CI 和 CD 通常一起配对，因为执行 CI 的许多相同引擎也可以实现 CD。CD 在许多组织中得到了接受和流行，这些组织强制执行适当的变更控制，并要求批准，以便软件发布过程能够进展到下一个阶段。由于 CI/CD 周围的许多概念都是以可重复的方式自动化的，团队可以寻求完全消除手动批准步骤的需要，一旦他们确信已经建立了可靠的框架。

在没有任何人为干预的情况下实施完全自动化的构建、测试、部署和发布过程的过程被称为**持续部署**。虽然许多软件项目从未完全实现持续部署，但通过实施 CI/CD 强调的概念，团队能够更快地产生真正的业务价值。在下一节中，我们将介绍 GitOps 作为改进应用程序及其配置管理的机制。

## 将 CI/CD 提升到下一个级别，使用 GitOps

Kubernetes 是一个支持声明式配置的平台。与任何编程语言编写的应用程序（如 Python、Golang 或 Java）通过 CI/CD 流水线的方式一样，Kubernetes 清单也可以实现许多相同的模式。清单也应该存储在源代码仓库（如 Git）中，并且可以经历相同类型的构建、测试和部署实践。在 Git 存储库中管理 Kubernetes 集群配置的生命周期的流行度上升，然后以自动化的方式应用这些资源，导致了 GitOps 的概念。GitOps 最早由软件公司 WeaveWorks 在 2017 年首次引入，自那时以来，作为管理 Kubernetes 配置的一种方式，GitOps 的流行度一直在增加。虽然 GitOps 在 Kubernetes 的背景下最为人所知，但其原则可以应用于任何云原生环境。

与 CI/CD 类似，已经开发了工具来管理 GitOps 流程。这些包括 Intuit 的 ArgoCD 和 WeaveWorks 的 Flux，这个组织负责创造 GitOps 这个术语。您不需要使用专门设计用于 GitOps 的工具，因为任何自动化工具，特别是设计用于管理 CI/CD 流程的工具，都可以被利用。传统 CI/CD 工具和专为 GitOps 设计的工具之间的关键区别在于 GitOps 工具能够不断观察 Kubernetes 集群的状态，并在当前状态与 Git 存储中定义的期望状态不匹配时应用所需的配置。这些工具利用了 Kubernetes 本身的控制器模式。

由于 Helm 图表最终被渲染为 Kubernetes 资源，它们也可以用于参与 GitOps 流程，并且许多前述的 GitOps 工具本身原生支持 Helm。我们将在本章的其余部分中看到如何利用 CI/CD 和 GitOps 来使用 Helm 图表，利用 Jenkins 作为 CI 和 CD 的首选工具。

# 设置我们的环境

在本章中，我们将开发两种不同的流水线，以演示如何自动化 Helm 周围的不同流程。

开始设置本地环境的步骤如下：

1.  首先，鉴于本章的内存要求增加，如果在[*第二章*]（B15458_02_Final_JM_ePub.xhtml#_idTextAnchor098）中未使用 4g 内存初始化`minikube`集群，则应删除该集群并使用 4g 内存重新创建。可以通过运行以下命令来完成：

```
$ minikube delete
$ minikube start --memory=4g
```

1.  Minikube 启动后，创建一个名为`chapter7`的新命名空间：

```
$ kubectl create namespace chapter7
```

此外，您还应该 fork Packt 存储库，这将允许您根据这些练习中描述的步骤对存储库进行修改：

1.  通过单击 Git 存储库上的**Fork**按钮来创建 Packt 存储库的分支：![图 7.1 - 选择 Fork 按钮来创建 Packt 存储库的分支](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.1.jpg)

图 7.1 - 选择 Fork 按钮来创建 Packt 存储库的分支

您必须拥有 GitHub 帐户才能 fork 存储库。创建新帐户的过程在[*第五章*]（B15458_05_Final_JM_ePub.xhtml#_idTextAnchor265）中有描述，*构建您的第一个 Helm 图表*。

1.  创建 Packt 存储库的分支后，通过运行以下命令将此分支克隆到本地计算机：

```
$ git clone https://github.com/$GITHUB_USERNAME/-Learn-Helm.git Learn-Helm
```

除了创建 Packt 存储库的分支外，您可能还希望从您的 Helm 存储库中删除`guestbook`图表，该图表是从您的 GitHub Pages 存储库中提供的，我们在[*第五章*]（B15458_05_Final_JM_ePub.xhtml#_idTextAnchor265）中创建了*构建您的第一个 Helm 图表*。虽然这并不是绝对必要的，但本章中的示例将假定一个干净的状态。

使用以下步骤从图表存储库中删除此图表：

1.  导航到 Helm 图表存储库的本地克隆。您会记得，我们建议的图表存储库的名称是`Learn-Helm-Chart-Repository`，因此在本章中我们将使用这个名称来引用您的基于 GitHub Pages 的图表存储库：

```
$ cd $LEARN_HELM_CHART_REPOSITORY_DIR
$ ls
guestbook-1.0.0.tgz   index.yaml   README.md
```

1.  从图表存储库中删除`guestbook-1.0.0.tgz`和`index.yaml`文件：

```
$ rm guestbook-1.0.0.tgz index.yaml
$ ls
README.md
```

1.  将这些更改推送到您的远程存储库：

```
$ git add --all
$ git commit -m 'Preparing for chapter 7'
$ git push origin master
```

1.  您应该能够在 GitHub 中确认您的图表和索引文件已被删除，只留下`README.md`文件：

图 7.2 - 您在图表存储库中应该看到的唯一文件是 README.md 文件

](image/Figure_7.2.jpg)

图 7.2 - 您在图表存储库中应该看到的唯一文件是 README.md 文件

现在您已经启动了 Minikube，创建了 Packt 存储库的一个分支，并从`Learn-Helm-Chart-Repository`中删除了 Guestbook 图表，让我们开始学习如何创建一个 CI 流水线来发布 Helm 图表。

# 创建一个 CI 流水线来构建 Helm 图表

CI 的概念可以应用于构建、测试、打包和发布 Helm 图表到图表存储库的图表开发人员的视角。在本节中，我们将描述使用端到端 CI 流水线来简化这个过程可能是什么样子，以及如何通过构建一个示例流水线来引导您。第一步是设计示例流水线所需的组件。

## 设计流水线

在之前的章节中，开发 Helm 图表主要是一个手动过程。虽然 Helm 提供了在 Kubernetes 集群中创建`test`钩子的自动化，但在代码更改后手动执行`helm lint`、`helm test`或`ct lint-and-install`命令以确保测试仍然通过。一旦代码更改后继续通过 linting 和测试，图表就可以通过运行`helm package`命令进行打包。如果使用 GitHub Pages 存储库（比如在*第五章*中创建的那个，*构建您的第一个 Helm 图表*），则通过运行`helm repo index`创建`index.yaml`文件，并将`index.yaml`文件以及打包的图表推送到 GitHub 存储库。

虽然手动调用每个命令当然是可行的，但随着您开发更多的 Helm 图表或添加更多的贡献者，这种工作流程可能变得越来越难以维持。使用手动工作流程，很容易允许未经测试的更改被应用到您的图表中，并且很难确保贡献者遵守测试和贡献指南。幸运的是，通过创建一个自动化发布流程的 CI 流水线，可以避免这些问题。

以下步骤概述了使用本书中讨论的命令和工具来进行示例 CI 工作流。它将假定生成的图表保存在 GitHub Pages 存储库中：

1.  图表开发人员对`git` monorepo 中的一个图表或一组图表进行代码更改。

1.  开发人员将更改推送到远程存储库。

1.  已修改的图表会通过运行`ct lint`和`ct install`命令在 Kubernetes 命名空间中自动进行 linting 和测试。

1.  如果 linting 和测试成功，图表将自动使用`helm package`命令打包。

1.  `index.yaml`文件将使用`helm repo index`命令自动生成。

1.  打包的图表和更新的`index.yaml`文件将自动推送到存储库。它们将被推送到`stable`或`staging`，具体取决于作业运行的分支。

在下一节中，我们将使用**Jenkins**执行这个过程。让我们首先了解一下 Jenkins 是什么以及它是如何工作的。

## 了解 Jenkins

Jenkins 是一个用于执行自动化任务和工作流程的开源服务器。它通常用于通过 Jenkins 的**管道即代码**功能创建 CI/CD 流水线，该功能在一个名为`Jenkinsfile`的文件中编写，该文件定义了 Jenkins 流水线。

Jenkins 流水线是使用 Groovy**领域特定语言**（**DSL**）编写的。Groovy 是一种类似于 Java 的语言，但与 Java 不同的是，它可以用作面向对象的脚本语言，适合编写易于阅读的自动化。在本章中，我们将带您了解两个已经为您准备好的`Jenkinsfile`文件。您不需要有任何关于从头开始编写`Jenkinsfile`文件的经验，因为深入研究 Jenkins 超出了本书的范围。话虽如此，到本章结束时，您应该能够将学到的概念应用到您选择的自动化工具中。虽然本章中介绍了 Jenkins，但其概念也可以应用于任何其他自动化工具。

当创建一个`Jenkinsfile`文件时，工作流程的一组定义的步骤将在 Jenkins 服务器本身上执行，或者委托给运行该作业的单独代理。还可以通过自动调度 Jenkins 代理作为单独的 Pod 集成额外的功能，每当启动构建时，简化代理的创建和管理。代理完成后，可以配置为自动终止，以便下一个构建可以在一个新的、干净的 Pod 中运行。在本章中，我们将使用 Jenkins 代理运行示例流水线。

Jenkins 还非常适合 GitOps 的概念，因为它提供了扫描源代码存储库以查找`Jenkinsfile`文件的能力。对于每个包含`Jenkinsfile`文件的分支，将自动配置一个新作业，该作业将从所需分支克隆存储库开始。这样可以很容易地测试新功能和修复，因为新作业可以自动创建并与其相应的分支一起使用。

在对 Jenkins 有基本了解之后，让我们在 Minikube 环境中安装 Jenkins。

安装 Jenkins

与许多通常部署在 Kubernetes 上的应用程序一样，Jenkins 可以使用来自 Helm Hub 的许多不同社区 Helm 图之一进行部署。在本章中，我们将使用来自**Codecentric**软件开发公司的 Jenkins Helm 图。添加`codecentric`图存储库以开始安装 Codecentric Jenkins Helm 图：

```
$ helm repo add codecentric https://codecentric.github.io/helm-charts
```

在预期的与 Kubernetes 相关的值中，例如配置资源限制和服务类型，`codecentric` Jenkins Helm 图包含其他用于自动配置不同 Jenkins 组件的 Jenkins 相关值。

由于配置这些值需要对超出本书范围的 Jenkins 有更深入的了解，因此为您提供了一个`values`文件，该文件将自动准备以下 Jenkins 配置：

+   添加未包含在基本镜像中的相关 Jenkins 插件。

+   配置所需的凭据以与 GitHub 进行身份验证。

+   配置专门设计用于测试和安装 Helm 图的 Jenkins 代理。

+   配置 Jenkins 以根据`Jenkinsfile`文件的存在自动创建新作业。

+   跳过通常在新安装启动时发生的手动提示。

+   禁用身份验证，以简化本章中对 Jenkins 的访问。

`values`文件还将配置以下与 Kubernetes 相关的细节：

+   针对 Jenkins 服务器设置资源限制。

+   将 Jenkins 服务类型设置为`NodePort`。

+   创建 Jenkins 和 Jenkins 代理在 Kubernetes 环境中运行作业和部署 Helm 图所需的 ServiceAccounts 和 RBAC 规则。

+   将 Jenkins 的`PersistentVolumeClaim`大小设置为`2Gi`。

该 values 文件可在[`github.com/PacktPublishing/-Learn-Helm/blob/master/jenkins/values.yaml`](https://github.com/PacktPublishing/-Learn-Helm/blob/master/jenkins/values.yaml)找到。浏览这些值的内容时，您可能会注意到`fileContent`下定义的配置包含 Go 模板。该值的开头如下所示：

![图 7.3 - Jenkins Helm 图表的 values.yaml 文件包含 Go 模板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.3.jpg)

图 7.3 - Jenkins Helm 图表的`values.yaml`文件包含 Go 模板

虽然 Go 模板通常在`values.yaml`文件中无效，但 Codecentric Jenkins Helm 图表向模板函数`tpl`提供了`fileContent`配置。在模板方面，这看起来如下所示：

```
{{- tpl .Values.fileContent }}
```

`tpl`命令将解析`fileContent`值作为 Go 模板，使其可以包含 Go 模板，即使它是在`values.yaml`文件中定义的。

在本章中，`fileContent`配置中定义的 Go 模板有助于确保 Jenkins 安装方式符合本章的要求。换句话说，模板将需要在安装过程中提供以下附加值：

+   `githubUsername`：GitHub 用户名

+   `githubPassword`：GitHub 密码

+   `githubForkUrl`：您的 Packt 存储库分支的 URL，该分支在本章的*技术要求*部分中提取

+   `githubPagesRepoUrl`：您的 GitHub Pages Helm 存储库的 URL，该存储库是在*第五章*结束时创建的，*构建您的第一个 Helm 图表*

请注意，这不是您静态站点的 URL，而是 GitHub 存储库本身的 URL，例如，https://github.com/$GITHUB_USERNAME/Learn-Helm-Chart-Repository.git。

前述列表中描述的四个值可以使用`--set`标志提供，也可以使用`--values`标志从额外的`values`文件中提供。如果选择创建单独的`values`文件，请确保不要将该文件提交和推送到源代码控制，因为它包含敏感信息。本章的示例偏向于使用`--set`标志来提供这四个值。除了上述描述的值之外，还应该使用`--values`标志提供 Packt 存储库中包含的`values.yaml`文件。

使用以下示例作为参考，使用`helm install`命令安装您的`Jenkins`实例：

```
$ helm install jenkins codecentric/jenkins \
  -n chapter7 --version 1.5.1 \
  --values Learn-Helm/jenkins/values.yaml \
  --set githubUsername=$GITHUB_USERNAME \
  --set githubPassword=$GITHUB_PASSWORD \
  --set githubForkUrl=https://github.com/$GITHUB_USERNAME/-Learn-Helm.git \
  --set githubPagesRepoUrl=https://github.com/$GITHUB_USERNAME/Learn-Helm-Chart-Repository.git
```

您可以通过对`chapter7`命名空间中的 Pod 运行监视来监视安装。

```
$ kubectl get Pods -n chapter7 -w
```

请注意，在极少数情况下，您的 Pod 可能会在`Init:0/1`阶段卡住。如果外部依赖出现可用性问题，比如 Jenkins 插件站点及其镜像正在经历停机时间，就会发生这种情况。如果发生这种情况，请尝试在几分钟后删除您的发布并重新安装它。

一旦您的 Jenkins Pod 在`READY`列下报告`1/1`，您的`Jenkins`实例就可以被访问了。复制并粘贴显示的安装后说明的以下内容以显示 Jenkins URL：

```
$ export NODE_PORT=$(kubectl get service --namespace chapter7 -o jsonpath='{.spec.ports[0].nodePort}' jenkins-master)
$ export NODE_IP=$(kubectl get nodes --namespace chapter7 -o jsonpath='{.items[0].status.addresses[0].address}')
echo "http://$NODE_IP:$NODE_PORT"
```

当您访问 Jenkins 时，您的首页应该看起来类似于以下屏幕截图：

![图 7.4-运行 Helm 安装后的 Jenkins 主页](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.4.jpg)

图 7.4-运行 Helm 安装后的 Jenkins 主页

如果图表安装正确，您会注意到一个名为**测试和发布 Helm 图表**的新作业被创建。在页面的左下角，您会注意到**构建执行器状态**面板，用于提供当前正在运行的活动作业的概览。当作业被创建时，将自动触发该作业，这就是为什么当您登录到 Jenkins 实例时会看到它正在运行。

现在 Jenkins 已安装并且其前端已经验证，让我们浏览一下 Packt 存储库中的示例`Jenkinsfile`文件，以了解 CI 管道的工作原理。请注意，本章节中我们不会显示`Jenkinsfile`文件的全部内容，因为我们只想简单地突出感兴趣的关键领域。文件的全部内容可以在 Packt 存储库中查看[`github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/Jenkinsfile`](https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/Jenkinsfile)。

## 理解管道

触发“测试和部署 Helm 图表”作业时发生的第一件事是创建一个新的 Jenkins 代理。通过利用`Learn-Helm/jenkins/values.yaml`中提供的值，Jenkins 图表安装会自动配置一个名为`chart-testing-agent`的 Jenkins 代理。以下一行指定该代理为此`Jenkinsfile`文件的代理：

```
agent { label 'chart-testing-agent' }
```

此代理由 Jenkins 图表值配置，使用 Helm 社区提供的图表测试图像运行。位于`quay.io/helmpack/chart-testing`的图表测试图像包含了*第六章*中讨论的许多工具，*测试 Helm 图表*。具体来说，该图像包含以下工具：

+   `helm`

+   `ct`

+   `yamllint`

+   `yamale`

+   `git`

+   `Kubectl`

由于此图像包含测试 Helm 图表所需的所有工具，因此可以将其用作执行 Helm 图表的 CI 的主要图像。

当 Jenkins 代理运行时，它会使用`githubUsername`和`githubPassword`进行身份验证，隐式地克隆您的 GitHub 分支，由`githubForkUrl`值指定。Jenkins 会自动执行此操作，因此不需要在`Jenkinsfile`文件中指定任何代码来执行此操作。

Jenkins 代理克隆您的存储库后，将开始执行`Jenkinsfile`文件中定义的阶段。阶段是管道中的逻辑分组，可以帮助可视化高级步骤。将执行的第一个阶段是 lint 阶段，其中包含以下命令：

```
sh 'ct lint'
```

前述命令中的`sh`部分是用于运行 bash shell 或脚本并调用`ct`工具的`lint`子命令。您会记得，此命令会针对已修改的所有图表的`Chart.yaml`和`values.yaml`文件对主分支进行检查，我们在*第六章*中已经讨论过这一点，*测试 Helm 图表*。

如果 linting 成功，流水线将继续进行到测试阶段，并执行以下命令：

```
sh 'ct install --upgrade'
```

这个命令也应该很熟悉。它会从主分支上的版本安装每个修改的图表，并执行定义的测试套件。它还确保从上一个版本的任何升级都成功，有助于防止回归。

请注意，前两个阶段可以通过运行单个`ct lint-and-install --upgrade`命令来合并。这仍然会导致有效的流水线，但这个示例将它们分成单独的阶段，可以更好地可视化执行的操作。

如果测试阶段成功，流水线将继续进行到打包图表阶段，执行以下命令：

```
sh 'helm package --dependency-update helm-charts/charts/*'
```

在这个阶段，命令将简单地打包`helm-charts/charts`文件夹下包含的每个图表。它还将更新和下载每个声明的依赖项。

如果打包成功，管道将继续进行到最后一个阶段，称为`推送图表到存储库`。这是最复杂的阶段，所以我们将把它分解成较小的步骤。第一步可以在这里看到：

```
// Clone GitHub Pages repository to a folder called 'chart-repo'
sh "git clone ${env.GITHUB_PAGES_REPO_URL} chart-repo"
// Determine if these charts should be pushed to 'stable' or 'staging' based on the branch
def repoType
if (env.BRANCH_NAME == 'master') {
  repoType = 'stable'
} else {
  repoType = 'staging'
}
// Create the corresponding 'stable' or 'staging' folder if it does not exist
def files = sh(script: 'ls chart-repo', returnStdout: true)
if (!files.contains(repoType)) {
  sh "mkdir chart-repo/${repoType}"
}
```

由于 Helm 图表存储库是一个单独的 GitHub Pages 存储库，我们必须克隆该存储库，以便我们可以添加新的图表并推送更改。一旦克隆了 GitHub Pages 存储库，就会设置一个名为`repoType`的变量，具体取决于 CI/CD 管道针对的分支。该变量用于确定前一阶段打包的图表应该推送到`stable`或`staging`图表存储库。

对于这个管道，`stable`意味着图表已经经过测试、验证并合并到主分支中。`staging`意味着图表正在开发中，尚未合并到主分支，也尚未正式发布。或者，您可以在切换到发布分支时在稳定存储库中发布图表，但是在这个例子中，我们将采用假设每次合并到主分支都是一个新发布的前一种方法。

`stable`和`staging`作为两个单独的图表存储库提供；这可以通过在 GitHub Pages 存储库的顶层创建两个单独的目录来完成：

```
Learn-Helm-Repository/
  stable/
  staging/
```

然后，稳定和暂存文件夹包含它们自己的`index.yaml`文件，以区分它们作为单独的图表存储库。

为了方便起见，前述管道摘录的最后一部分会在管道执行依赖于其存在的分支时自动创建`stable`或`staging`文件夹。

现在确定了图表应该推送到的存储库类型，我们继续进行管道的下一个阶段，如下所示：

```
// Move charts from the packaged-charts folder to the corresponding 'stable' or 'staging' folder
sh "mv packaged-charts/*.tgz chart-repo/${repoType}"
// Generate the updated index.yaml
sh "helm repo index chart-repo/${repoType}"
// Update git config details
sh "git config --global user.email 'chartrepo-robot@example.com'"
sh "git config --global user.name 'chartrepo-robot'"
```

第一条命令将从前一阶段复制每个打包的图表到`stable`或`staging`文件夹。接下来，使用`helm repo index`命令更新`stable`或`staging`的`index.yaml`文件，以反映已更改或添加的图表。

需要记住的一点是，如果我们使用不同的图表存储库解决方案，比如**ChartMuseum**（由 Helm 社区维护的图表存储库解决方案），则不需要使用`helm repo index`命令，因为当 ChartMuseum 接收到新的打包 Helm 图表时，`index.yaml`文件会自动更新。对于不会自动计算`index.yaml`文件的实现，比如 GitHub Pages，`helm repo index`命令是必要的，正如我们在这个管道中所看到的。

前面片段的最后两个命令设置了`git`的`username`和`email`，这些是推送内容到`git`存储库所必需的。在本例中，我们将用户名设置为`chartrepo-robot`，以表示 CI/CD 过程促进了`git`交互，我们将设置邮箱为`(mailto:chartrepo-robot@example.com)`作为示例值。您可能希望邮箱代表负责维护图表存储库的组织。

最后一步是推送更改。这个操作在最终的管道片段中被捕获，如下所示：

```
// Add and commit the changes
sh 'git add --all'
sh "git commit -m 'pushing charts from branch ${env.BRANCH_NAME}'"
withCredentials([usernameColonPassword(credentialsId: 'github-auth', variable: 'USERPASS')]) {
    script {
    // Inject GitHub auth and push to the master branch, where the charts are being served
    def authRepo = env.GITHUB_PAGES_REPO_URL.replace('://', "://${USERPASS}@")
    sh "git push ${authRepo} master"
    }
}
```

打包的图表首先使用`git add`和`git commit`命令添加和提交。接下来，使用`git push`命令对存储库进行推送，使用名为`github-auth`的凭据。这个凭据是在安装过程中从`githubUsername`和`githubPassword`值创建的。`github-auth`凭据允许您安全地引用这些机密，而不会在管道代码中以明文形式打印出来。

请注意，Helm 社区发布了一个名为`Chart Releaser`的工具（[`github.com/helm/chart-releaser`](https://github.com/helm/chart-releaser)），可以作为使用`helm repo index`命令生成`index.yaml`文件并使用`git push`上传到 GitHub 的替代方案。`Chart Releaser`工具旨在通过管理包含在 GitHub Pages 中的 Helm 图表来抽象一些额外的复杂性。

我们决定在本章中不使用这个工具来实现管道，因为在撰写本文时，`Chart Releaser`不支持 Helm 3。

既然我们已经概述了 CI 管道，让我们通过一个示例执行来运行一遍。

## 运行管道

正如我们之前讨论的，当我们安装 Jenkins 时，这个流水线的第一次运行实际上是自动触发的。该作业针对主分支运行，并且可以通过单击 Jenkins 登陆页面上的**测试和发布 Helm Charts**链接来查看。您会注意到有一个成功的作业针对主分支运行了：

![图 7.5 - 流水线的第一次运行](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.5.jpg)

图 7.5 - 流水线的第一次运行

Jenkins 中的每个流水线构建都有一个关联的日志，其中包含执行的输出。您可以通过在左侧选择蓝色圆圈旁边的**#1**链接，然后在下一个屏幕上选择**控制台输出**来访问此构建的日志。此构建的日志显示第一个阶段`Lint`成功，显示了这条消息：

```
All charts linted successfully
----------------------------------
No chart changes detected.
```

这是我们所期望的，因为从主分支的角度来看，没有任何图表发生变化。在安装阶段也可以看到类似的输出：

```
All charts installed successfully
-----------------------------------
No chart changes detected.
```

因为 Lint 和 Install 阶段都没有错误，所以流水线继续到了 Package Charts 阶段。在这里，您可以查看输出：

```
+ helm package --dependency-update helm-charts/charts/guestbook helm-charts/charts/nginx
Successfully packaged chart and saved it to: /home/jenkins/agent/workspace/t_and_Release_Helm_Charts_master/guestbook-1.0.0.tgz
Successfully packaged chart and saved it to: /home/jenkins/agent/workspace/t_and_Release_Helm_Charts_master/nginx-1.0.0.tgz
```

最后，流水线通过克隆您的 GitHub Pages 存储库，在其中创建一个`stable`文件夹，将打包的图表复制到`stable`文件夹中，将更改提交到 GitHub Pages 存储库本地，并将更改推送到 GitHub。我们可以观察到每个添加到我们存储库的文件都在以下行中输出：

```
+ git commit -m 'pushing charts from branch master'
[master 9769f5a] pushing charts from branch master
 3 files changed, 32 insertions(+)
 create mode 100644 stable/guestbook-1.0.0.tgz
 create mode 100644 stable/index.yaml
 create mode 100644 stable/nginx-1.0.0.tgz
```

您可能会好奇在自动推送后您的 GitHub Pages 存储库是什么样子。您的存储库应该如下所示，其中包含一个新的`stable`文件夹，其中包含 Helm 图表：

![图 7.6 - CI 流水线完成后存储库的状态](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.6.jpg)

图 7.6 - CI 流水线完成后存储库的状态

在`stable`文件夹中，您应该能够看到三个不同的文件，两个单独的图表和一个`index.yaml`文件：

![图 7.7 - `stable`文件夹的内容](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.7.jpg)

图 7.7 - `stable`文件夹的内容

这个第一个流水线构建成功地创建了一组初始的`stable`图表，但没有演示在被认为是稳定并且可以供最终用户使用之前，新图表如何进行 linting 和测试。为了演示这一点，我们需要从主分支切出一个功能分支来修改一个或多个图表，将更改推送到功能分支，然后在 Jenkins 中启动一个新的构建。

首先，从主分支创建一个名为 `chapter7` 的新分支：

```
$ cd $PACKT_FORK_DIR
$ git checkout master
$ git checkout -b chapter7
```

在这个分支上，我们将简单地修改`ngnix`图表的版本以触发图表的 linting 和测试。NGINX 是一个 Web 服务器和反向代理。它比我们在本书中一直使用的 Guestbook 应用程序要轻量得多，因此，为了避免 Jenkins 在您的 Minikube 环境中运行时可能出现的任何资源限制，我们将在本示例中使用 Packt 存储库中的`ngnix`图表。

在`helm-charts/charts/nginx/Chart.yaml`文件中，将图表的版本从`1.0.0`更改为`1.0.1`：

```
version: 1.0.1
```

运行 `git status` 确认已检测到变化：

```
$ git status
On branch chapter7
Changes not staged for commit:
  (use 'git add <file>...' to update what will be committed)
  (use 'git checkout -- <file>...' to discard changes in working directory)
        modified:   helm-charts/charts/nginx/Chart.yaml
no changes added to commit (use 'git add' and/or 'git commit -a')
```

注意`ngnix`的`Chart.yaml`文件已经被修改。添加文件，然后提交更改。最后，您可以继续将更改推送到您的分支：

```
$ git add helm-charts
$ git commit -m 'bumping NGINX chart version to demonstrate chart testing pipeline'
$ git push origin chapter7
```

在 Jenkins 中，我们需要触发仓库扫描，以便 Jenkins 可以检测并针对此分支启动新的构建。转到**测试和发布 Helm Charts**页面。您可以通过点击顶部标签栏上的**测试和发布 Helm Charts**标签轻松实现：

![图 7.8 – 测试和发布 Helm Charts 页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.8.jpg)

图 7.8 – 测试和发布 Helm Charts 页面

选择后，点击左侧菜单中的**立即扫描多分支流水线**按钮。这允许 Jenkins 检测到您的新分支并自动启动新的构建。扫描应在大约 10 秒内完成。刷新页面，新的`chapter7`分支应如下出现在页面上：

![图 7.9 – 扫描新的 chapter7 分支后的测试和部署 Helm Charts 页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.9.jpg)

图 7.9 – 扫描新的`chapter7`分支后的测试和部署 Helm Charts 页面

由于`chapter7`作业包含经过修改的 Helm 图表，并使用图表测试工具进行测试，因此`chapter7`作业的运行时间将比主作业长。您可以通过导航到`chapter7`的控制台输出来观察此流水线的运行情况。从**测试和发布 Helm 图表**概述页面，选择*第七章*分支，然后在左下角选择**#1**链接。最后，选择**控制台输出**链接。如果您在流水线仍在运行时导航到此页面，您将实时收到日志更新。等到流水线结束，在那里应该显示以下消息：

```
Finished: SUCCESS
```

在控制台输出日志的开始处，注意`ct lint`和`ct install`命令是针对`ngnix`图表运行的，因为这是唯一发生更改的图表：

```
Charts to be processed:
---------------------------------------------------------------
 nginx => (version: '1.0.1', path: 'helm-charts/charts/nginx')
```

每个命令的附加输出应该已经很熟悉，因为它与*第六章*中描述的输出相同，*测试 Helm 图表*。

在您的 GitHub Pages 存储库中，您应该看到`staging`文件夹中的`ngnix`图表的新版本，因为它没有构建在主分支上：

![图 7.10 - “staging”文件夹的内容](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.10.jpg)

图 7.10 - `staging`文件夹的内容

要发布`nginx-1.0.1.tgz`图表，您需要将`chapter7`分支合并到主分支，这将导致该图表被推送到稳定存储库。在命令行上，将您的`chapter7`分支合并到主分支并将其推送到`remote`存储库：

```
$ git checkout master
$ git merge chapter7
$ git push origin master
```

在 Jenkins 中，通过返回到**测试和发布 Helm 图表**页面并点击**master**作业来导航到主流水线作业。您的屏幕应该如下所示：

![图 7.11 - 测试和发布 Helm 图表项目的主作业](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.11.jpg)

图 7.11 - 测试和发布 Helm 图表项目的主作业

一旦进入此页面，点击左侧的**立即构建**链接。再次注意日志中的内容，图表测试被跳过，因为图表测试工具将克隆与主分支进行了比较。由于内容相同，工具确定没有需要测试的内容。构建完成后，导航到您的 GitHub Pages 存储库，确认新的`nginx-1.0.1.tgz`图表位于`stable`存储库下：

![图 7.12 - 添加新的 nginx 图表后存储库的状态](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.12.jpg)

图 7.12 - 添加新的`nginx`图表后存储库的状态

您可以通过在本地添加`helm repo add`来验证这些图表是否已正确部署到 GitHub Pages 的`stable`存储库。在*第五章*中，*构建您的第一个 Helm 图表*，您添加了 GitHub Pages 存储库的根位置。但是，我们修改了文件结构以包含`stable`和`staging`文件夹。如果仍然配置，您可以通过运行以下命令来删除此存储库：

```
$ helm repo remove learnhelm
```

可以使用`stable`存储库的更新位置再次添加存储库：

```
$ helm repo add learnhelm $GITHUB_PAGES_SITE_URL/stable
```

请注意，`$GITHUB_PAGES_SITE_URL`的值引用 GitHub 提供的静态站点，而不是您实际的`git`存储库。您的 GitHub Pages 站点 URL 应该类似于[`$GITHUB_USERNAME.github.io/Learn-Helm-Repository/stable`](https://$GITHUB_USERNAME.github.io/Learn-Helm-Repository/stable)。确切的链接可以在 GitHub Pages 存储库的**设置**选项卡中找到。

在添加`stable`存储库后，运行以下命令查看在两个主构建过程中构建和推送的每个图表：

```
$ helm search repo learnhelm --versions
```

您应该看到三个结果，其中两个包含构建和推送的`nginx`图表的两个版本：

![图 7.13 - `helm search repo`命令的结果](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.13.jpg)

图 7.13 - `helm search repo`命令的结果

在本节中，我们讨论了如何通过 CI 管道管理 Helm 图表的生命周期。通过使用提供的示例遵循自动化工作流程，您可以在发布图表给最终用户之前轻松执行常规的 linting 和测试。

虽然本节主要关注 Helm 图表的 CI，但 CD 和 GitOps 也可以用于将 Helm 图表部署到不同的环境。我们将在下一节中探讨如何构建 CD 管道。

# 创建一个使用 Helm 部署应用程序的 CD 管道

CD 管道是一组可重复部署到一个或多个不同环境的步骤。在本节中，我们将创建一个 CD 管道，以部署我们在上一节中测试并推送到 GitHub Pages 存储库的`nginx`图表。还将通过引用保存到`git`存储库的`values`文件来利用 GitOps。

让我们设计需要包括在此管道中的高级步骤。

## 设计管道

在以前的章节中，使用 Helm 部署到 Kubernetes 环境是一个手动过程。然而，这个 CD 管道旨在在抽象使用 Helm 的同时部署到多个不同的环境。

以下步骤描述了我们将在本节中涵盖的 CD 工作流程。

1.  添加包含`nginx`图表发布的稳定 GitHub Pages 存储库。

1.  将`nginx`图表部署到开发环境。

1.  将`nginx`图表部署到**质量保证**（**QA**）环境。

1.  等待用户批准管道以继续进行生产部署。

1.  将`nginx`图表部署到生产环境。

CD 工作流包含在单独的`Jenkinsfile`文件中，与先前为 CI 管道创建的文件不同。在创建`Jenkinsfile`文件之前，让我们更新 Minikube 和 Jenkins 环境，以便执行 CD 流程。

## 更新环境

开发、QA 和生产环境将由本地 Minikube 集群中的不同命名空间建模。虽然我们通常不建议允许非生产（开发和 QA）和生产环境共存于同一集群中，但为了演示我们的示例 CD 流程，我们将这三个环境放在一起。

创建`dev`、`qa`和`prod`命名空间来表示每个环境：

```
$ kubectl create ns dev
$ kubectl create ns qa
$ kubectl create ns prod
```

您还应该删除在上一节中创建的`chapter7`分支。应删除此分支，因为当创建新的 CD 管道时，Jenkins 将尝试针对存储库的每个分支运行它。为简单起见，并避免资源限制，我们建议仅使用主分支进行推进。

使用以下命令从存储库中删除`chapter7`分支：

```
$ git push -d origin chapter7
$ git branch -D chapter7
```

最后，您需要升级您的 Jenkins 实例以设置一个名为`GITHUB_PAGES_SITE_URL`的环境变量。这是您在 GitHub Pages 中图表存储库的位置，格式为[`$GITHUB_USERNAME.github.io/Learn-Helm-Chart-Repository/stable`](https://$GITHUB_USERNAME.github.io/Learn-Helm-Chart-Repository/stable)。CD 流水线中引用了该环境变量，以通过`helm repo add`添加`stable` GitHub Pages 图表存储库。要添加此变量，您可以通过使用`--reuse-values`标志重新使用先前应用的值，同时使用`--set`指定一个名为`githubPagesSiteUrl`的附加值。

执行以下命令来升级您的 Jenkins 实例：

```
$ helm upgrade jenkins codecentric/jenkins \
  -n chapter7 --version 1.5.1 \
  --reuse-values --set githubPagesSiteUrl=$GITHUB_PAGES_SITE_URL
```

此次升级将导致 Jenkins 实例重新启动。您可以通过针对`chapter7`命名空间的 Pod 运行 watch 来等待 Jenkins Pod 准备就绪：

```
$ kubectl get Pods -n chapter7 -w
```

当 Jenkins Pod 指示`1/1`个容器已准备就绪时，该 Jenkins Pod 可用。

一旦 Jenkins 准备就绪，通过使用上一节中相同的 URL 访问 Jenkins 实例。您应该会找到另一个作业，名为`Deploy NGINX Chart`，它代表了 CD 流水线：

![图 7.14-升级 Jenkins 版本后的 Jenkins 首页](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.14.jpg)

图 7.14-升级 Jenkins 版本后的 Jenkins 首页

当设置了 GITHUB_PAGES_SITE_URL 时，此作业将在`values.yaml`文件中配置为创建（以帮助改进本章流程）。

请注意，与 CI 流水线一样，CD 流水线也会自动启动，因为它是首次被检测到。在我们审查此流水线的日志之前，让我们先来看看构成 CD 流水线的过程。

## 理解流水线

在本节中，我们将仅审查流水线的关键领域，但完整的 CD 流水线已经编写好，并位于[`github.com/PacktPublishing/-Learn-Helm/blob/master/nginx-cd/Jenkinsfile`](https://github.com/PacktPublishing/-Learn-Helm/blob/master/nginx-cd/Jenkinsfile)。

与之前的 CI 流水线一样，为了测试和发布 Helm 图表，CD 流水线首先通过动态创建一个新的 Jenkins 代理作为运行图表测试镜像的 Kubernetes Pod 来开始：

```
agent { label 'chart-testing-agent' }
```

虽然我们在这个流水线中没有使用`ct`工具，但是图表测试镜像包含了执行`nginx`部署所需的 Helm CLI，因此该镜像足以用于这个示例 CD 流水线。然而，也可以创建一个更小的镜像，删除未使用的工具也是可以接受的。

一旦代理被创建，Jenkins 会隐式克隆您的分支，就像在 CI 流水线中一样。

流水线的第一个明确定义的阶段称为“设置”，它将托管在 GitHub Pages 上的您的`stable`图表存储库添加到 Jenkins 代理上的本地 Helm 客户端中。

```
sh "helm repo add learnhelm ${env.GITHUB_PAGES_SITE_URL}"
```

一旦存储库被添加，流水线就可以开始将 NGINX 部署到不同的环境中。下一个阶段称为“部署到开发环境”，将 NGINX 图表部署到您的`dev`命名空间：

```
dir('nginx-cd') {
  sh "helm upgrade --install nginx-${env.BRANCH_NAME} learnhelm/nginx --values common-values.yaml --values dev/values.yaml -n dev --wait"
}
```

您可能注意到这个阶段的第一个细节是`dir('nginx-cd')`闭包。这是`Jenkinsfile`语法，用于设置其中包含的命令的工作目录。我们将很快更详细地解释`nginx-cd`文件夹。

您还可以看到，这个阶段使用提供的`--install`标志运行`helm upgrade`命令。`helm upgrade`通常针对已经存在的发布执行，并且如果尝试针对不存在的发布执行则会失败。然而，`--install`标志会在发布不存在时安装图表。如果发布已经存在，`helm upgrade`命令会升级发布。`--install`标志对于自动化流程非常方便，比如本节中描述的 CD 流水线，因为它可以避免您需要执行检查来确定发布的存在。

关于这个`helm upgrade`命令的另一个有趣细节是它两次使用了`--values`标志——一次针对名为`common-values.yaml`的文件，一次针对名为`dev/values.yaml`的文件。这两个文件都位于`nginx-cd`文件夹中。以下内容位于`nginx-cd`文件夹中：

```
nginx-cd/
  dev/
    values.yaml
  qa/
    values.yaml
  prod/
    values.yaml
  common-values.yaml
  Jenkinsfile
```

在将应用程序部署到不同的环境时，您可能需要稍微修改应用程序的配置，以使其能够与环境中的其他服务集成。`dev`、`qa`和`prod`文件夹下的每个`values`文件都包含一个环境变量，该变量根据部署的环境设置在 NGINX 部署上。例如，这里显示了`dev/values.yaml`文件的内容：

```
env:
 - name: ENVIRONMENT
   value: dev
```

类似地，这里显示了`qa/values.yaml`文件的内容：

```
env:
 - name: ENVIRONMENT
   value: qa
```

`prod/values.yaml`文件的内容如下：

```
env:
 - name: ENVIRONMENT
   value: prod
```

虽然在这个示例中部署的 NGINX 图表是直接的，并且不严格要求指定这些值，但您会发现将环境特定的配置分开放在单独的`values`文件中，使用这里展示的方法对于复杂的真实用例非常有帮助。然后可以通过将相应的 values 文件传递给`helm upgrade --install`命令来应用安装，其中`${env}`表示`dev`、`qa`或`prod`。

正如其名称所示，`common-values.yaml`文件用于所有部署环境中通用的值。这个示例的`common-values.yaml`文件写成如下形式：

```
service:
 type: NodePort
```

这个文件表示在安装图表期间创建的每个 NGINX 服务都应该具有`NodePort`类型。由于它们没有在`common-values.yaml`文件或单独的`values.yaml`环境文件中被覆盖，NGINX 图表的`values.yaml`文件中设置的所有其他默认值也被应用到每个环境中。

重要的一点是，您的应用程序应该在每个部署环境中尽可能相同地部署。任何改变运行中的 Pod 或容器的物理属性的值都应该在`common-values.yaml`文件中指定。这些配置包括但不限于以下内容：

+   副本计数

+   资源请求和限制

+   服务类型

+   镜像名称

+   镜像标签

+   `ImagePullPolicy`

+   卷挂载

修改与特定环境服务集成的配置可以在单独的环境`values`文件中进行修改。这些配置可能包括以下内容：

+   指标或监控服务的位置

+   数据库或后端服务的位置

+   应用/入口 URL

+   通知服务

回到 CD 流水线的`Deploy to Dev`阶段中使用的 Helm 命令，`--values common-values.yaml`和`--values dev/values.yaml`标志的组合将这两个`values`文件合并到`dev`中安装`nginx`图表。该命令还使用`-n dev`标志表示部署应该在`dev`命名空间中执行。此外，`--wait`标志用于暂停`nginx` Pod，直到它被报告为`ready`。

继续进行流水线，部署到`dev`后的下一个阶段是烟雾测试。该阶段运行以下命令：

```
sh 'helm test nginx -n dev'
```

NGINX 图表包含一个测试钩子，用于检查 NGINX Pod 的连接。如果`test`钩子能够验证可以与 Pod 建立连接，则测试将返回为成功。虽然`helm test`命令通常用于图表测试，但它也可以作为在 CD 过程中执行基本烟雾测试的良好方法。烟雾测试是部署后进行的测试，以确保应用的关键功能按设计工作。由于 NGINX 图表测试不会以任何方式干扰正在运行的应用程序或部署环境的其余部分，因此`helm test`命令是确保 NGINX 图表成功部署的适当方法。

烟雾测试后，示例 CD 流水线运行下一个阶段，称为`部署到 QA`。该阶段包含一个条件，评估流水线正在执行的当前分支是否是主分支，如下所示：

```
when {
  expression {
    return env.BRANCH_NAME == 'master'
  }
}
```

该条件允许您使用功能分支来测试`values.yaml`文件中包含的部署代码，而无需将其提升到更高的环境。这意味着只有主分支中包含的 Helm 值应该是生产就绪的，尽管这不是您在 CD 流水线中发布应用时可以采取的唯一策略。另一种常见的策略是允许在以`release/`前缀开头的发布分支上进行更高级别的推广。

`部署到 QA`阶段中使用的 Helm 命令显示如下：

```
dir('nginx-cd') {
    sh "helm upgrade --install nginx-${env.BRANCH_NAME} learnhelm/nginx --values common-values.yaml --values qa/values.yaml -n qa --wait"
}
```

鉴于您对`部署到 Dev`阶段和常见值与特定环境值的分离的了解，`部署到 QA`的代码是可以预测的。它引用了`qa/values.yaml`文件中的 QA 特定值，并传递了`-n qa`标志以部署到`qa`命名空间。

在部署到`qa`或类似的测试环境之后，您可以再次运行前面描述的烟雾测试，以确保`qa`部署的基本功能正常工作。您还可以在这个阶段包括任何其他自动化测试，以验证在部署到`prod`之前应用的功能是否正常。这些细节已从此示例流水线中省略。

流水线的下一个阶段称为`等待输入`：

```
stage('Wait for Input') {
    when {
        expression {
            return env.BRANCH_NAME == 'master'
        }
    }
    steps {
        container('chart-testing') {
            input 'Deploy to Prod?'
        }
    }
}
```

这个输入步骤暂停了 Jenkins 流水线，并用“部署到生产环境？”的问题提示用户。在运行作业的控制台日志中，用户有两个选择 - “继续”和“中止”。虽然可以自动执行生产部署而无需此手动步骤，但许多开发人员和公司更喜欢在“非生产”和“生产”部署之间设置一个人为的门。这个“输入”命令为用户提供了一个机会，让用户决定是否继续部署或在`qa`阶段之后中止流水线。

如果用户决定继续，将执行最终阶段，称为“部署到生产环境”：

```
dir('nginx-cd') {
  sh "helm upgrade --install nginx-${env.BRANCH_NAME} learnhelm/nginx --values common-values.yaml --values prod/values.yaml -n prod --wait"
}
```

这个阶段几乎与“部署到 Dev”和“部署到 QA”阶段相同，唯一的区别是生产特定的`values`文件和作为`helm upgrade --install`命令的一部分定义的`prod`命名空间。

现在示例 CD 流水线已经概述，让我们观察流水线运行，该流水线是在您升级 Jenkins 实例时启动的。

## 运行流水线

要查看此 CD 流水线的运行情况，请导航到“部署 NGINX 图”作业的主分支。在 Jenkins 首页，点击**部署 NGINX 图**和**主分支**。您的屏幕应该如下所示：

![图 7.15 - 部署 NGINX 图 CD 流水线的主分支](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.15.jpg)

图 7.15 - 部署 NGINX 图 CD 流水线的主分支

一旦您导航到此页面，请点击**＃1**链接并导航到控制台日志：

![图 7.16 - 部署 NGINX 图 CD 流水线的控制台输出页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.16.jpg)

图 7.16 - 部署 NGINX 图 CD 流水线的控制台输出页面

当您导航到日志时，您应该会看到一个提示，上面写着“部署到生产环境？”。我们很快会解决这个问题。首先，让我们回顾一下日志的开头，以便查看到目前为止流水线的执行情况。

您可以看到的第一个部署是`dev`部署：

```
+ helm upgrade --install nginx-master learnhelm/nginx --values common-values.yaml --values dev/values.yaml -n dev --wait
Release 'nginx-master' does not exist. Installing it now.
NAME: nginx-master
LAST DEPLOYED: Thu Apr 30 02:07:55 2020
NAMESPACE: dev
STATUS: deployed
REVISION: 1
NOTES:
1\. Get the application URL by running these commands:
  export NODE_PORT=$(kubectl get --namespace dev -o jsonpath='{.spec.ports[0].nodePort}' services nginx-master)
  export NODE_IP=$(kubectl get nodes --namespace dev -o jsonpath='{.items[0].status.addresses[0].address}')
  echo http://$NODE_IP:$NODE_PORT
```

然后，您应该会看到由`helm test`命令运行的冒烟测试：

```
+ helm test nginx-master -n dev
Pod nginx-master-test-connection pending
Pod nginx-master-test-connection pending
Pod nginx-master-test-connection succeeded
NAME: nginx-master
LAST DEPLOYED: Thu Apr 30 02:07:55 2020
NAMESPACE: dev
STATUS: deployed
REVISION: 1
TEST SUITE:     nginx-master-test-connection
Last Started:   Thu Apr 30 02:08:03 2020
Last Completed: Thu Apr 30 02:08:05 2020
Phase:          Succeeded
```

冒烟测试之后是`qa`部署：

```
+ helm upgrade --install nginx-master learnhelm/nginx --values common-values.yaml --values qa/values.yaml -n qa --wait
Release 'nginx-master' does not exist. Installing it now.
NAME: nginx-master
LAST DEPLOYED: Thu Apr 30 02:08:09 2020
NAMESPACE: qa
STATUS: deployed
REVISION: 1
```

这将带我们到输入阶段，我们在首次打开日志时看到的：

![图 7.17 - 部署到生产环境之前的输入步骤](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_7.17.jpg)

图 7.17 - 部署到生产环境之前的输入步骤

点击**继续**链接以继续流水线执行，点击**中止**将导致流水线失败，并阻止生产部署的发生。然后您将看到`prod`部署发生：

```
+ helm upgrade --install nginx-master learnhelm/nginx --values common-values.yaml --values prod/values.yaml -n prod --wait
Release 'nginx-master' does not exist. Installing it now.
NAME: nginx-master
LAST DEPLOYED: Thu Apr 30 03:46:22 2020
NAMESPACE: prod
STATUS: deployed
REVISION: 1
```

最后，如果生产部署成功，您将在流水线结束时看到以下消息：

```
[Pipeline] End of Pipeline
Finished: SUCCESS
```

您可以手动验证部署是否成功。运行 `helm list` 命令查找 `nginx-master` 发布版本：

```
$ helm list -n dev
$ helm list -n qa
$ helm list -n prod
```

每个命令都应该列出每个命名空间中的 `nginx` 发布版本：

```
NAME 	            NAMESPACE	    REVISION  	
nginx-master	      dev      	    1
```

您还可以使用 `kubectl` 列出每个命名空间中的 Pod，并验证 NGINX 是否已部署：

```
$ kubectl get Pods -n dev
$ kubectl get Pods -n qa
$ kubectl get Pods -n prod
```

每个命名空间的结果将类似于以下内容（`dev` 还将有一个在冒烟测试阶段执行的已完成测试 Pod）：

```
NAME                    READY   STATUS    RESTARTS   AGE
nginx-fcb5d6b64-rmc2j   1/1     Running   0          46m
```

在本节中，我们讨论了如何在 Kubernetes 中的 CD 流水线中使用 Helm 来部署应用程序到多个环境中。该流水线依赖于 GitOps 实践，将配置（`values.yaml`文件）存储在源代码控制中，并引用这些文件来正确配置 NGINX。了解了 Helm 如何在 CD 环境中使用后，您现在可以清理您的 Minikube 集群。

# 清理

要清理本章练习中的 Minikube 集群，请删除 `chapter7`、`dev`、`qa` 和 `prod` 命名空间：

```
$ kubectl delete ns chapter7
$ kubectl delete ns dev
$ kubectl delete ns qa
$ kubectl delete ns prod
```

您还可以关闭您的 Minikube 虚拟机：

```
$ minikube stop
```

# 摘要

在 CI 和 CD 流水线中调用 Helm CLI 是进一步抽象 Helm 提供的功能的有效方式。图表开发人员可以通过编写 CI 流水线来自动化端到端的图表开发过程，包括代码检查、测试、打包和发布到图表存储库。最终用户可以编写 CD 流水线，使用 Helm 在多个不同的环境中部署图表，利用 GitOps 来确保应用程序可以作为代码部署和配置。编写流水线有助于开发人员和公司通过抽象和自动化过程更快、更轻松地扩展应用程序，避免了可能变得繁琐并引入人为错误的过程。

在下一章中，我们将介绍另一种抽象 Helm CLI 的选项——编写 Helm operator。

# 进一步阅读

要了解有关图表测试容器映像的更多信息，请访问[`helm.sh/blog/chart-testing-intro/`](https://helm.sh/blog/chart-testing-intro/)。

要了解更多关于 Jenkins 和 Jenkins 流水线的信息，请查阅 Jenkins 项目文档（[`jenkins.io/doc/`](https://jenkins.io/doc/)）、Jenkins 流水线文档（[`jenkins.io/doc/book/pipeline/`](https://jenkins.io/doc/book/pipeline/)）和多分支流水线插件文档（[`plugins.jenkins.io/workflow-multibranch/`](https://plugins.jenkins.io/workflow-multibranch/)）。

# 问题

1.  CI 和 CD 之间有什么区别？

1.  CI/CD 和 GitOps 之间有什么区别？

1.  CI/CD 流水线创建和发布 Helm 图表包括哪些高级步骤？

1.  CI 给图表开发者带来了哪些优势？

1.  CD 流水线部署 Helm 图表包括哪些高级步骤？

1.  CD 流水线给图表的最终用户带来了哪些优势？

1.  如何将应用程序的配置作为代码在多个环境中进行维护？如何减少`values`文件中的样板代码？
