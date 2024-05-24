# Helm 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/AB61831A08B0763334412D2ABCB093BB`](https://zh.annas-archive.org/md5/AB61831A08B0763334412D2ABCB093BB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：Helm 图表开发

在本节中，您将学习 Helm 图表的结构。您将学习如何从头开始构建 Helm 图表，并学习调试和测试图表的技巧。

本节包括以下章节：

*第四章，理解 Helm 图表*

*第五章，构建您的第一个 Helm 图表*

*第六章，测试 Helm 图表*


# 第四章：理解 Helm 图表

在上一章中，您学习了如何从最终用户的角度使用 Helm，将其作为一个包管理器来安装应用程序到 Kubernetes。以这种方式使用 Helm 不需要任何 Kubernetes 专业知识或对应用程序的深入理解，因为所有资源和逻辑都包含在 Helm 图表的一部分中。您需要熟悉的唯一概念是图表提供的值，以便自定义安装。

现在我们将从使用 Helm 图表转向理解它们是如何工作和创建的。

为此，我们将涵盖以下主题：

+   理解 YAML 格式

+   理解图表模板

+   理解图表定义

+   生命周期管理

+   记录 Helm 图表

# 技术要求

本节要求在本地机器上安装`helm`二进制文件。有关此工具的安装和配置在*第二章*中有介绍，准备 Kubernetes 和 Helm 环境。

# 理解 YAML 格式

YAML 不是一种标记语言（YAML）是一种用于创建可读性强的配置文件的文件格式。它是配置 Kubernetes 资源最常用的文件格式，也是 Helm 图表中许多文件的格式。

YAML 文件遵循键值格式来声明配置。让我们探索 YAML 键值构造。

## 定义键值对

这里展示了一个最基本的 YAML 键值对示例：

```
name: LearnHelm
```

在前面的示例中，`name`键被赋予了`LearnHelm`值。在 YAML 中，键和值由冒号（:）分隔。冒号左边的字符代表键，而冒号右边的字符代表值。

在 YAML 格式中，间距很重要。以下行不构成键值对：

```
name:LearnHelm
```

请注意，冒号和`LearnHelm`字符串之间缺少空格。这将导致解析错误。冒号和值之间必须存在空格。

虽然前面的示例代表了一个简单的键值对，但 YAML 允许用户配置具有嵌套元素或块的更复杂的配对。下面是一个示例：

```
resources:
  limits:
    cpu: 100m
    memory: 512Mi
```

前面的示例演示了一个包含两个键值对的资源对象的映射：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/012.jpg)

键是通过遵循 YAML 块下的缩进来确定的。每个缩进都会在键的名称中添加一个点（`.`）分隔符。当 YAML 块中不再有缩进时，就已经到达了键的值。按照通常的做法，YAML 中的缩进应该使用两个空格，但用户可以提供任意多的空格，只要在整个文档中保持一致。

重要提示：

YAML 不支持**制表符**，使用制表符会导致解析错误。

通过理解 YAML 键值对，现在让我们来探索一些常见的值类型。

## 值类型

YAML 文件中的值可以是不同的类型。最常见的类型是字符串，它是一个文本值。字符串可以通过用引号括起来来声明，但这并不总是必需的。如果一个值包含至少一个字母或特殊字符，那么这个值被认为是一个字符串，无论是否有引号。多行字符串可以通过使用管道（`|`）符号来设置，如下所示：

```
configuration: |
  server.port=8443
  logging.file.path=/var/log
```

值也可以是整数。当一个数值字符没有用引号括起来时，它就是一个整数值。以下的 YAML 声明了一个整数值：

```
replicas: 1
```

将其与以下 YAML 进行比较，该 YAML 将副本分配给一个字符串值：

```
replicas: '1'
```

布尔值也经常被使用，可以用 true 或 false 来声明：

```
ingress:
  enable: true
```

这个 YAML 将`ingress.enable`设置为`true`布尔值。其他可接受的布尔值包括`yes`、`no`、`on`、`off`、`y`、`n`、`Y`和`N`。

值也可以设置为更复杂的类型，比如列表。在 YAML 中，列表中的项目由破折号（`-`）符号标识。

以下演示了一个 YAML 列表：

```
servicePorts:
  - 8080
  - 8443
```

这个 YAML 将`servicePorts`设置为整数列表（比如`8080`和`8443`）。这种语法也可以用来描述对象列表：

```
deployment:
  env:
    - name: MY_VAR
      value: MY_VALUE
    - name: SERVICE_NAME
      value: MY_SERVICE
```

在这种情况下，`env`被设置为一个包含`name`和`value`字段的对象列表。列表在 Kubernetes 和 Helm 配置中经常被使用，理解它们对于充分利用 Helm 是很有价值的。

虽然 YAML 在 Kubernetes 和 Helm 的世界中更常用，因为它易于阅读，但**JavaScript 对象表示**（**JSON**）格式也可以使用。让我们简要描述一下这种格式。

JSON 格式

YAML 是另一种广泛使用的格式 JSON 的超集。JSON 是一串键值对，类似于 YAML。主要区别在于，YAML 依赖于空格和缩进来正确配置键值对，而 JSON 依赖于大括号和方括号。

以下示例将前面的 YAML 示例转换为 JSON 格式：

```
{
  'deployment': {
    'env': [
      {
        'name': 'MY_VAR',
        'value': 'MY_VALUE'
      },
      {
        'name': 'SERVICE_NAME',
        'value': 'MY_SERVICE'
      }
    ]
  }
```

JSON 中的所有键都用引号括起来，并放在冒号之前：

+   花括号（`{`）以类似于 YAML 中缩进表示块的方式表示块。

+   方括号（``）以类似于 YAML 中破折号表示列表的方式表示列表。

YAML 和 JSON 格式有许多其他构造，但这个介绍提供了足够的信息来理解它们如何在 Helm 图表中使用。

在下一节中，我们将讨论 Helm 图表文件结构，您可能会注意到其中包含几个 YAML 和 JSON 文件。

Helm 图表结构

正如您可能还记得之前的章节，Helm 图表是 Kubernetes 资源的打包，允许用户将各种复杂性的应用程序部署到 Kubernetes。然而，为了被视为 Helm 图表，必须遵循一定的文件结构：

```
my-chart/
  # chart files and directories
```

最佳实践是将顶层目录命名为 Helm 图表的名称。这不是技术要求，但它可以更简单地识别 Helm 图表的名称。对于前面的示例文件结构，Helm 图表的名称很可能是`my-chart`。

在顶层目录下是组成 Helm 图表的文件和目录。以下表格显示了每个可能的文件和目录：

![

在本章中，我们将探讨这些文件，以了解如何创建 Helm 图表。我们将首先通过了解图表模板的工作原理来允许动态生成 Kubernetes 资源。

# 理解图表模板

Helm 图表的主要目的是创建和管理组成应用程序的 Kubernetes 资源。这是通过图表模板实现的，值作为参数来自定义这些模板。在本节中，我们将讨论 Helm 模板和值的功能。

Helm 图表必须包含一个`templates/`目录，该目录定义要部署的 Kubernetes 资源（尽管如果图表声明了依赖项，则不严格需要此目录）。`templates/`目录下的内容是由 Kubernetes 资源组成的 YAML 文件。`templates/`目录的内容可能类似于以下内容：

```
templates/
  configmap.yaml
  deployment.yaml
  service.yaml
```

然后`configmap.yaml`资源可能如下所示：

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}
data:
  configuration.txt: |-
    {{ .Values.configurationData }}
```

您可能会质疑先前的示例是否是有效的 YAML 语法。这是因为`configmap.yaml`文件实际上是一个 Helm 模板，它将根据一定的一组值修改此资源的配置，以生成有效的 YAML 资源。开放和关闭的大括号代表了**Golang**（**Go**）模板的输入文本，这些将在安装或升级过程中被移除。

让我们更多地了解 Go 模板以及它们如何用于生成 Kubernetes 资源文件。

## Go 模板

**Go**是由 Google 于 2009 年开发的一种编程语言。它是 Kubernetes、Helm 和 Kubernetes 和容器社区中许多其他工具使用的编程语言。Go 编程语言的核心组件是模板，可以用来生成不同格式的文件。在 Helm 的情况下，Go 模板用于在 Helm 图表的`templates/`目录下生成 Kubernetes YAML 资源。

Go 模板控制结构和处理从两个开放的大括号（`{{`）开始，并以两个结束的大括号（`}}`）结束。虽然这些标点符号可能出现在`templates/`目录下的本地文件中，但它们在安装或升级过程中进行的处理过程中被移除。

我们将在《第五章》[*构建您的第一个 Helm 图表*]中深入探讨 Go 模板，您将在其中构建自己的 Helm 图表。在本章中，我们将讨论 Go 模板的常见功能，作为这一功能的介绍，然后进行一些实际操作。我们将从 Go 模板提供的一系列功能开始讨论，从参数化开始。

### 使用值和内置对象对字段进行参数化

Helm 图表在其图表目录中包含一个`values.yaml`文件。该文件声明了图表的所有默认值，这些值由 Go 模板引用，并由 Helm 处理以动态生成 Kubernetes 资源。

图表的`values.yaml`文件可以定义如下的值：

```
## chapterNumber lists the current chapter number
chapterNumber: 4
## chapterName gives a description of the current chapter
chapterName: Understanding Helm Charts
```

以井号（`#`）开头的行是注释（在执行过程中被忽略），应提供有关它们描述的值的详细信息，以便用户了解应如何应用它们。注释还可以包括值的名称，以便在搜索值时出现注释。文件中的其他行表示键值对。本章开头描述了 YAML 格式的介绍。

以`.Values`开头的 Go 模板将引用在`values.yaml`文件中定义的值，或者在安装或升级期间使用`--set`或`--values`标志传递的值。

以下示例表示模板在处理之前的样子：

```
env:
  - name: CHAPTER_NUMBER
    value: {{ .Values.chapterNumber }}
  - name: CHAPTER_NAME
    values: {{ .Values.chapterName }}
```

模板处理后，YAML 资源的片段呈现如下：

```
env:
  - name: CHAPTER_NUMBER
    value: 4
  - name: CHAPTER_NAME
    values: Understanding Helm Charts
```

用于引用图表值的`.Values`构造是一个内置对象，可用于参数化。Helm 文档中可以找到内置对象的完整列表（https://helm.sh/docs/chart_template_guide/builtin_objects/），但最常见的对象在下表中描述：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/new04.jpg)

每个对象前面的点（`.`）表示对象范围。点后面跟着对象名称将范围限制为该对象。例如，`.Values`范围只能使图表的值可见；`.Release`范围只能使`Release`对象下的字段可见；而`.`范围表示全局范围，使所有这些对象可见，以及在前面的表中定义的常见对象。

### values.schema.json 文件

在谈论值和参数化时，让我们花一点时间讨论`values.schema.json`文件，这是图表目录中可能包含的文件之一。`values.schema.json`文件用于在`values`文件中强制执行特定的模式。此模式可用于在安装或升级期间验证提供的值。

以下片段显示了`values.schema.json`文件的外观：

```
{
  '$schema': 'https://json-schema.org/draft-07/schema#',
  'properties': {
    'replicas': {
      'description': 'number of application instances to deploy',
      'minimum': 0
      'type' 'integer'
    },
    . . .
  'title': 'values',
  'type': 'object'
}
```

有了这个模式文件，`replicas`值应该设置为`0`作为最小值。添加到此文件的其他值会对可以提供的值施加额外的限制。这个文件是确保用户只提供图表模板中支持的值的好方法。

虽然 Go 模板允许图表开发人员对 Helm 图表进行参数化，但它们也允许开发人员在 YAML 文件中提供条件逻辑。我们将在下面探讨这个特性。

### 使用流程控制进行精细化模板处理

虽然参数化允许图表开发人员用特定值替换字段，但 Go 模板还提供了控制模板流程和结构的能力。这可以通过以下关键字（在 Go 中称为`actions`）来实现：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/04.jpg)

在图表模板化过程中，有时需要包含或排除某些 Kubernetes 资源或某些资源的某些部分。`if…else`操作可以用于此目的。以下来自部署模板的片段包括一个条件块：

```
readinessProbe:
{{- if .Values.probeType.httpGet }}
  httpGet:
    path: /healthz
    port: 8080
    scheme: HTTP
{{- else }}
  tcpSocket:
    port: 8080
{{- end }}
  initialDelaySeconds: 30
  periodSeconds: 10
```

`if`块用于有条件地设置`readinessProbe`段。如果`probeType.httpGet`值计算为`true`或非空，则将模板化`httpGet` `readinessProbe`。否则，创建的`readinessProbe`将是`tcpSocket` `readinessProbe`类型。大括号中使用的破折号用于指示在处理后应删除空格。在开括号后使用破折号删除括号前的空格，在闭括号前使用破折号删除括号后的空格。

图表开发人员还可以使用`with`操作来修改值的范围。当引用的值块深度嵌套时，这个操作非常有用。它可以通过减少引用深度嵌套值所需的字符数量来简化模板文件的可读性和可维护性。

以下代码描述了一个`values`文件，其中包含了深度嵌套的值：

```
application:
  resources:
    limits:
      cpu: 100m
      memory: 512Mi
```

没有`with`操作，这些值将在`template`文件中被引用，如下所示：

```
cpu: {{ .Values.application.resources.limits.cpu }}
memory: {{ .Values.application.resources.limits.memory }}
```

`with`操作允许开发人员修改这些值的范围，并使用缩短的语法引用它们：

```
{{- with .Values.application.resources.limits }}
cpu: {{ .cpu }}
memory: {{ .memory }}
{{- end }}
```

最后，开发人员可以使用`range`操作执行重复的操作。这个操作允许开发人员循环遍历一个值列表。假设一个图表有以下值：

```
servicePorts:
  - name: http
    port: 8080
  - name: https
    port: 8443
  - name: jolokia
    port: 8778
```

上述代码提供了一个`servicePorts`列表，可以循环遍历，如下例所示：

```
spec:
  ports:
{{- range .Values.servicePorts }}
  - name: {{ - name }}
  port: {{ .port }}
{{- end }}
```

`with`和`range`操作限制了提供的对象的范围。在`range`示例中，`range`作用于`.Values.servicePorts`对象，将点（.）符号的范围限制在此对象下定义的值。要在`range`下实施全局范围，其中所有值和内置对象都被引用，开发人员应该使用美元符号（`$`）符号作为前缀引用，如下所示：

```
{{- range .Values.servicePorts }}
  - name: {{ $.Release.Name }}-{{ .name }}
  port: {{ .port }}
{{- end }}
```

除了图表的值，开发人员还可以创建变量来帮助渲染资源。我们将在下一节中探讨这一点。

### 模板变量

尽管它们不像其他模板特性那样常用，但图表开发人员可以在他们的图表模板中创建变量，以提供额外的处理选项。这种方法的常见用途是流程控制，但模板变量也可以用于其他用例。

图表模板中的变量定义如下：

```
{{ $myvar := 'Hello World!' }}
```

将`myvar`变量设置为`Hello World!`字符串。变量也可以分配给对象，比如图表的值：

```
{{ $myvar := .Values.greeting }}
```

然后在模板中以以下方式引用设置的变量：

```
data:
  greeting.txt: |
    {{ $myvar }}
```

使用变量的最佳情况之一是在范围块中，其中变量被设置为捕获列表迭代的索引和值：

```
data:
  greetings.txt: |
{{- range $index, $value := .Values.greetings }}
    Greeting {{ $index }}: {{ $value }}
{{- end }}
```

结果可以如下呈现：

```
data:
  greetings.txt: |
    Greeting 0: Hello
    Greeting 1: Hola
    Greeting 2: Hallo
```

变量还可以简化地图迭代的处理，如下所示：

```
data:
  greetings.txt: |
{{- range $key, $val := .Values.greetings }}
    Greeting in {{ $key }}: {{ $val }}
{{- end }}
```

可能的结果可能如下所示：

```
data:
  greetings.txt: |
    Greeting in English: Hello
    Greeting in Spanish: Hola
    Greeting in German: Hallo
```

最后，变量可以用来引用当前范围之外的值。

考虑以下`with`块：

```
{{- with .Values.application.configuration }}
My application is called {{ .Release.Name }}
{{- end }}
```

这样的模板将无法处理，因为`.Release.Name`不在`.Values.application.configuration`的范围内。可以通过在`with`块上方设置一个变量为`.Release.Name`来解决这个问题：

```
{{ $appName := .Release.Name }}
{{- with .Values.application.configuration }}
My application is called {{ $appName }}
{{- end }}
```

虽然这是解决这个问题的一种可能的方法，但使用美元符号来引用全局范围的方法更受欢迎，因为它需要更少的配置行，并且在图表复杂性增加时更容易阅读。

流程控制和变量是强大的概念，可以动态生成资源。除了流程控制，图表开发人员还可以利用函数和管道来帮助资源的渲染和格式化。

### 使用函数和管道进行复杂处理

Go 提供了函数和管道的概念，以在模板内对数据进行复杂处理。

Go 模板函数类似于您在其他语言和结构中遇到的其他函数。函数包含旨在消耗某些输入并根据提供的输入提供输出的逻辑。

对于 Go 模板，可以使用以下语法调用函数：

```
functionName arg1 arg2 . . .
```

常用的一个 Go 函数是`indent`函数。此函数用于缩进指定数量的字符的字符串，以确保字符串格式正确，因为 YAML 是一种对空格敏感的标记语言。`indent`函数接受缩进的空格数和应该缩进的字符串作为输入。

以下模板说明了这一点：

```
data:
  application-config: |-
{{ indent 4 .Values.config }}
```

这个例子通过`4`个空格缩进`config`值中包含的字符串，以确保该字符串在`application-config` YAML 键下正确缩进。

Helm 提供的另一个结构是管道。管道是从 UNIX 借鉴的概念，其中一个命令的输出被作为输入传递给另一个命令：

```
cat file.txt | grep helm
```

前面的示例显示了 UNIX 管道。管道的左侧（`|`）是第一个命令，右侧是第二个命令。第一个命令`cat file.txt`打印名为`file.txt`的文件的内容，并将其作为输入传递给`grep helm`命令，该命令过滤第一个命令的输出以获取单词`helm`。

Go 管道的工作方式类似。这可以再次通过`indent`函数来演示：

```
data:
  application-config: |-
{{ .Values.config | indent 4 }}
```

这也将`config`值缩进 4 个空格。管道最适合用于将多个命令链接在一起。第三个命令可以添加到管道中，称为`quote`，它在最终模板化产品周围添加引号引号：

```
data:
  application-config: |-
{{ .Values.config | indent 4 | quote }}
```

因为这是以管道形式编写的，所以阅读起来很容易和自然。

Helm 图表中可以使用许多不同的 Go 模板函数。这些函数可以在 Go 文档 https://golang.org/pkg/text/template/#hdr-Functions 和 Sprig 模板库 http://masterminds.github.io/sprig/中找到。您在图表开发过程中可能使用的一些常见 Go 模板函数如下：

+   `date`：格式化日期

+   `default`：设置默认值

+   `fail`：失败的模板渲染

+   `include`：执行 Go 模板并返回结果

+   `nindent`：类似于 indent，但在缩进之前添加一个新行

+   `indent`：通过一定数量的空格缩进文本

+   `now`：显示当前日期/时间

+   `quote`：将字符串用引号括起来

+   `required`：要求用户输入

+   `splitList`：将字符串拆分为字符串列表

+   `toYaml`：将字符串转换为 YAML 格式

Go 模板语言还包括以下布尔运算符，可以在`if`操作中使用，以进一步控制生成 YAML 资源：

+   `and`

+   `or`

+   `not`

+   `eq`（等于的缩写）

+   `ne`（不等于的缩写）

+   `lt`（小于的缩写）

+   `le`（小于或等于的缩写）

+   `gt`（大于的缩写）

+   `ge`（大于或等于的缩写）

除了生成 Kubernetes 资源外，Go 模板还可以用于创建可以在具有重复模板的 YAML 资源中重用的函数。这可以通过创建命名模板来实现，下一节将对其进行描述。

### 使用命名模板实现代码重用

在创建模板文件时，可能会有 Kubernetes 资源中的样板或重复的 YAML 块。

一个例子是资源的标签，可以指定如下：

```
labels:
  'app.kubernetes.io/instance': {{ .Release.Name }}
  'app.kubernetes.io/managed-by': {{ .Release.Service }}
```

为了保持一致，这些标签中的每一个都可以添加到 Helm 图表中的每个资源中。如果图表包含许多不同的 Kubernetes 资源，那么在每个文件中包含所需的标签可能会很麻烦，特别是如果需要修改标签或者将来需要向每个资源中添加新标签。

Helm 提供了一种称为命名模板的构造，允许图表开发人员创建可重用的模板，以减少样板文件。命名模板定义在`templates/`目录下，是以下划线开头并以`.tpl`文件扩展名结尾的文件。许多图表都使用名为`_helpers.tpl`的文件来包含命名模板，尽管文件不一定要被称为`helpers`。

要在`tpl`文件中创建一个命名模板，开发人员可以利用`define`操作。以下示例创建了一个命名模板，可用于封装资源标签：

```
{{- define 'mychart.labels' }}
labels:
  'app.kubernetes.io/instance': {{ .Release.Name }}
  'app.kubernetes.io/managed-by': {{ .Release.Service }}
{{- end }}
```

`define`操作以模板名称作为参数。在前面的示例中，模板名称称为`mychart.labels`。命名模板的常见约定是`$CHART_NAME.$TEMPLATE_NAME`，其中`$CHART_NAME`是 Helm 图表的名称，`$TEMPLATE_NAME`是一个简短的描述性名称，描述模板的目的。

`mychart.labels`名称意味着该模板是本地的`mychart` Helm 图表，并将为应用到的资源生成标签。

要在 Kubernetes YAML 模板中使用命名模板，可以使用`include`函数，其用法如下：

```
include [TEMPLATE_NAME] [SCOPE]
```

`TEMPLATE_NAME`参数是应该处理的命名模板的名称。`SCOPE`参数是应该处理的值和内置对象的范围。大多数情况下，这个参数是一个点（`.`）来表示当前顶层范围，但如果命名模板引用当前范围之外的值，则应该使用美元符号（`$`）。

以下示例演示了如何使用`include`函数来处理命名模板：

```
metadata:
  name: {{ .Release.Name }}
{{- include 'mychart.labels' . | indent 2 }}
```

这个例子首先将资源的名称设置为发布的名称。然后使用`include`函数来处理标签，并且通过管道声明每行缩进两个空格。处理完成后，发布中的资源`template-demonstration`可能如下所示：

```
metadata:
  name: template-demonstration
  labels:
    'app.kubernetes.io/instance': template-demonstration
    'app.kubernetes.io/managed-by': Helm
```

Helm 还提供了一个`template`操作，可以扩展命名模板。这个操作与`include`具有相同的用法，但有一个主要限制——它不能在管道中用于提供额外的格式化和处理。`template`操作用于简单地内联显示数据。由于这个限制，图表开发者应该使用`include`函数而不是`template`操作，因为`include`具有与`template`相同的功能，但还提供了管道处理的额外好处。

在下一节中，我们将学习如何使用命名模板来减少跨多个不同图表的样板文件。

### 图书馆图表

Helm 图表在`Chart.yaml`文件中定义了一个`type`字段，可以设置为`application`或`library`。应用程序图表用于将完整的应用程序部署到 Kubernetes。这是最常见的图表类型，也是默认设置。但是，图表也可以定义为库图表。这种类型的图表不用于部署应用程序，而是用于提供可以在多个不同图表中使用的命名模板。在前一节中定义的`labels`示例中就是这种用例的一个例子。开发人员可以维护多个不同的图表，这些图表的资源具有相同的标签。开发人员可以声明一个库图表，该图表提供用于生成资源标签的命名模板作为依赖项，而不是在每个图表的`_helpers.tpl`文件中定义相同的命名模板。

虽然 Helm 最常用于创建传统的 Kubernetes 资源，但它也可以创建**Custom Resources**（**CRs**），我们将在下一节中解释。

### 模板 CRs

**CRs**用于创建不属于 Kubernetes API 的资源。您可能希望使用此功能来增强 Kubernetes 提供的功能。CRs 可以使用 Helm 模板创建，例如本机 Kubernetes 资源，但必须首先有一个定义 CR 的**Custom Resource Definition (CRD)**。如果在创建 CR 之前不存在 CRD，则安装将失败。

Helm 图表可以包括一个`crds/`文件夹，其中包含必须在安装模板之前呈现的 CRDs。这里显示了一个示例`crds/`文件夹：

```
crds/
  my-custom-resource-crd.yaml
```

文件`my-custom-resource-crd.yaml`可能包含以下内容：

```
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: my-custom-resources.learnhelm.io
spec:
  group: learnhelm.io
  names:
    kind: MyCustomResource
    listKind: MyCustomResourceList
    plural: MyCustomResources
    singular: MyCustomResource
    scope: Namespaced
    version: v1
```

模板/目录然后可以包含 MyCustomResource 资源的一个实例。

```
templates/
  my-custom-resource.yaml
```

这样的文件结构将确保在`templates/`目录下定义的 CR 之前安装`MyCustomResource` CRD。

重要说明：

此功能要求用户是集群管理员，因为创建 CRDs 需要提升的权限。如果您不是集群管理员，最好请管理员事先创建您的 CRDs。如果这样做，`crds/`文件夹就不需要包含在您的图表中，因为 CRDs 已经存在于集群中。

到目前为止，我们已经详细介绍了 Helm 模板。总之，Helm 模板是您的 Helm 图表的“大脑”，用于生成 Kubernetes 资源。我们将亲自体验编写 Helm 模板，以及本章讨论的其他主题，在*第五章*中，*构建您的第一个 Helm 图表*。

现在，让我们继续讨论 Helm 图表基础知识，与图表模板同等重要的一个主题是`Chart.yaml`文件。

# 了解图表定义

`Chart.yaml`文件，也称为图表定义，是声明有关 Helm 图表的不同元数据的资源。此文件是必需的，如果它没有包含在图表的文件结构中，您将收到以下错误：

```
Error: validation: chart.metadata is required
```

在*第三章*，*安装您的第一个 Helm 图表*中，我们通过运行`helm show chart`命令来探索**Bitnami 的 WordPress 图表**的图表定义。再次运行此命令来回忆这个图表定义。我们将假设 Bitnami 图表存储库已经被添加，因为这个任务是在*第三章*，*安装您的第一个 Helm 图表*中执行的：

```
$ helm show chart bitnami/wordpress --version 8.1.0
```

以下列出了 wordpress 图表的图表定义。

![图 4.1 - Bitnami 图表存储库的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_4.1.jpg)

图 4.1 - wordpress 图表的图表定义。

图表定义，或`Chart.yaml`文件，可以包含许多不同的字段。一些字段是必需的，而大多数其他字段是可选的，只有在必要时才能提供。

现在我们对`Chart.yaml`文件有了基本的了解，接下来我们将在下一节中探讨文件的必填字段。

## 必填字段

图表定义必须包含包含关键图表元数据的以下字段：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/05.jpg)

让我们更详细地探讨这些必填字段：

+   `apiVersion`字段可以设置为两个不同的值：

`v1`

`v2`

+   如果`apiVersion`字段设置为`v1`，这意味着该图表遵循传统的图表结构。这是在 Helm 3 发布之前使用的`apiVersion`值，在图表结构中支持了额外的`requirement.yaml`文件，并且在图表定义中不支持`type`字段。Helm 3 向后兼容`apiVersion`值`v1`，但新图表应该设置为`apiVersion`值`v2`，以避免使用废弃的功能。

+   `name`字段用于定义 Helm 图表的名称。该值应等于包含 Helm 图表文件的顶级目录的名称。Helm 图表的名称将出现在`helm search`命令的搜索结果中，以及`helm list`命令，以返回用于发布的图表的名称。该字段的值应该简洁而具有描述性，用一个简短的名称描述图表安装的应用程序，如`wordpress`或`redis-cluster`。在名称中区分不同单词时，使用短横线分隔单词是常见的约定。有时，名称将被写成一个单词，比如`rediscluster`。

+   `version` 字段用于确定 Helm chart 的版本。版本必须遵循**语义化版本**（**SemVer**）`2.0.0` 格式才能成为有效的图表版本。SemVer 根据 `Major.Minor.Patch` 格式描述版本，其中当引入破坏性更改时，`Major` 版本应增加，当发布向后兼容的功能时，`Minor` 版本应增加，当修复错误时，`Patch` 版本应增加。当增加 `Minor` 版本时，`Patch` 版本设置为 `0`。当增加 `Major` 版本时，`Minor` 和 `Patch` 版本都重置为 `0`。图表开发人员在增加图表版本时应特别小心，因为它们用于指示何时发布破坏性更改、新功能和错误修复。

虽然这三个字段是 `Chart.yaml` 文件中唯一需要的字段，但还有许多可选字段可以包含在其中，以向图表添加附加元数据。

让我们来看看其他可能的 `Chart.yaml` 字段。

可选元数据

除了必填字段外，还有许多可选字段可用于提供有关图表的其他详细信息，如下表所述：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/013.jpg)

其中一些字段提供简单的元数据，以向用户显示有关 Helm chart 的信息。然而，其他字段用于修改 Helm chart 的行为。其中第一个字段是 `type` 字段，可以设置为 `application` 或 `library`。如果设置为 `application`，则图表部署 Kubernetes 资源。如果设置为 `library`，则图表通过助手模板的形式为其他图表提供函数。

可以修改 Helm chart 行为的第二个字段是 `dependencies` 字段，将在下一节中讨论。

## 管理图表依赖项

图表依赖项用于安装 Helm chart 可能依赖的其他图表资源。一个例子是 `wordpress` 图表，它将 `mariaDB` 图表声明为依赖项以保存后端数据。通过使用 `mariadb` 依赖项，WordPress 图表无需从头开始定义其资源。

通过填充 `dependencies` 字段在 `Chart.yaml` 文件中声明依赖项。以下是 `wordpress` 图表定义中的相关片段：

![图 4.2 – wordpress 图表定义的片段](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_4.2.jpg)

图 4.2 - 在 wordpress Helm 图表中声明的 mariadb 依赖项。

虽然此示例显示了单个依赖项`mariadb`，但`dependencies`块可以定义多个依赖项的列表。

`dependencies`块包含许多不同的字段，可以应用于修改图表依赖项管理的行为。这些字段在下表中定义：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/022.jpg)

`dependencies`块下的最小必需字段是`name`、`repository`和`version`字段。如前面的`wordpress`依赖片段所示，依赖的名称是 mariadb，存储库可以在[`kubernetes-charts.storage.googleapis.com`](https://kubernetes-charts.storage.googleapis.com/)找到。这将在提供的存储库中搜索一个 Helm 图表，其`Chart.yaml`文件中的`name`字段为`mariadb`。`dependencies`块的`version`字段指定应包含的图表版本。这可以固定到特定版本，如`7.0.0`，也可以指定通配符版本。前面示例中列出的依赖项提供了一个通配符版本`7.x.x`，它指示 Helm 下载与通配符匹配的图表的最新版本。

现在，了解了所需的依赖项字段，让我们学习如何下载声明的依赖项。

## 下载依赖项

可以使用下表中列出的`helm dependency`子命令下载依赖项：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/03.jpg)

要首次下载依赖项，可以运行`helm dependency update`命令，将每个依赖项下载到给定 Helm 图表的`charts/`目录中：

```
$ helm dependency update $CHART_PATH
```

`helm dependency update`命令从存储库中下载以`.tgz`文件扩展名的`GZip`存档形式的依赖项。此命令还生成一个名为`Chart.lock`的文件。`Chart.lock`文件类似于`Chart.yaml`文件。但是，`Chart.yaml`文件包含图表依赖项的期望状态，而`Chart.lock`文件定义了应用的依赖项的实际状态。

可以在这里看到一个`Chart.lock`文件的示例：

![图 4.3 - 一个 Chart.lock 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_4.3.jpg)

图 4.3 - 一个`Chart.lock`文件

将其与一个简单的相应的`Chart.yaml`文件进行比较：

![图 4.4 - 相应的 Chart.yaml 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_4.4.jpg)

图 4.4 - 相应的`Chart.yaml`文件

在`Chart.yaml`文件中，您可以看到指定的`mariadb`依赖项的版本是`7.x.x`，但是`Chart.lock`文件中的版本是`7.3.1`。这是因为`Chart.yaml`文件指示 Helm 下载`7.x.x`版本的最新版本，实际下载的版本是`7.3.1`。

有了`Chart.lock`文件，Helm 能够重新下载最初下载的确切依赖项，以防`charts/`目录被删除或需要重建。这可以通过针对图表运行`helm dependency build`命令来实现：

```
$ helm dependency build $CHART_PATH
```

因为你可以使用`helm dependency build`命令下载依赖项，所以可以省略`charts/`目录，以减少存储库的大小。

随着时间的推移，`7.x.x`版本的新版本将可用。可以再次运行`helm dependency update`命令来协调此依赖项，这意味着将下载最新可用版本，并且`Chart.lock`文件将重新生成。如果将来想要从`8.x.x`版本下载或者想要将依赖项固定到特定版本，比如`7.0.0`，可以在`Chart.yaml`文件中设置并运行`helm dependency update`。

`helm dependency list`命令可用于查看保存在本地计算机上的 Helm 图表的已下载依赖项：

```
$ helm dependency list $CHART_NAME
```

您将看到类似以下的输出：

![图 4.5 - CHART_NAME 命令的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_4.5.jpg)

图 4.5 - "helm dependency list"输出

`STATUS`列确定了依赖项是否已成功下载到`charts/`目录。如果状态显示为`ok`，则已下载依赖项。如果状态显示为`missing`，则尚未下载依赖项。

默认情况下，`Chart.yaml`文件中声明的每个依赖项都将被下载，但可以通过提供`dependencies`块的`condition`或`tags`字段来修改，我们将在下一节讨论。

## 条件依赖

`condition`和`flags`字段可以在安装或升级过程中有条件地包含依赖项。考虑`Chart.yaml`文件中的一个示例`dependencies`块：

```
dependencies:
  - name: dependency1
    repository: https://example.com
    version: 1.x.x
    condition: dependency1.enabled
    tags:
      - monitoring
  - name: dependency2
    repository: https://example.com
    version: 2.x.x
    condition: dependency2.enabled
    tags:
      - monitoring
```

请注意`condition`和`tags`字段的包含。`condition`字段列出了用户应提供的值，或者在图表的`values.yaml`文件中设置的值。如果评估为`true`，`condition`字段将导致图表作为依赖项被包括进来。如果为`false`，则不会包括依赖项。可以通过用逗号分隔每个条件来定义多个条件，如下所示：

```
condition: dependency1.enabled, global.dependency1.enabled
```

设置条件的最佳实践是遵循`chartname.enabled`值格式，其中每个依赖项根据依赖项的图表名称设置唯一的条件。这允许用户通过遵循直观的值模式来启用或禁用单个图表。如果条件值未包含在图表的`values.yaml`文件中，或者用户未提供该字段，则将忽略此字段。

`condition`字段用于启用或禁用单个依赖项，`tags`字段用于启用或禁用依赖项组。在前面的`dependencies`块中，两个依赖项都列出了一个名为`monitoring`的标签。这意味着如果启用了`monitoring`标签，两个依赖项都会被包括进来。如果`monitoring`标签设置为`false`，则依赖项将被省略。通过在父图表的`values.yaml`文件中的`tags` YAML 对象下设置它们来启用或禁用标签，如下所示：

```
tags:
  monitoring: true
```

依赖项可以通过遵循列表的 YAML 语法在`Chart.yaml`文件中定义多个标签。只需要一个标签被评估为`true`，依赖项就会被包括进来。

重要提示：

如果忽略了依赖项的所有标签，依赖项将默认包括进来。

在本节中，我们讨论了如何有条件地声明依赖关系。接下来，我们将讨论如何覆盖和引用依赖项的值。

## 覆盖和引用子图表的值

默认情况下，属于依赖图表（也称为**子图表**）的值可以通过将它们包装在名称设置为与子图表相同的映射中来被覆盖或引用。想象一个名为`my-dep`的子图表，支持以下值：

```
replicas: 1
servicePorts:
  - 8080
  - 8443
```

当此图表作为依赖项安装时，可以通过在父图表的`values.yaml`文件中设置`my-dep` YAML 对象来覆盖这些值，如下所示：

```
my-dep:
  replicas: 3
  servicePorts:
    - 8080
    - 8443
    - 8778
```

前面的例子覆盖了`my-dep`中定义的`replicas`和`servicePorts`的值，将`replicas`设置为`3`，并将`8778`添加到`servicePorts`中。这些值可以通过点表示法在父图的模板中引用，例如`my-dep.replicas`。除了覆盖和引用值之外，您还可以通过定义`import-values`字段直接导入依赖值，下一节将对此进行解释。

## 使用`import-values`导入值

`Chart.yaml`文件的`dependencies`块支持一个`import-values`字段，可用于导入子图的默认值。该字段有两种工作方式。第一种方式是提供要从子图导入的键列表。为了使其工作，子图必须在`exports`块下声明值，如下所示：

```
exports:
  image:
    registry: 'my-registry.io'
    name: learnhelm/my-image
    tag: latest
```

然后父图可以在`Chart.yaml`文件中定义`import-values`字段：

```
dependencies:
  - name: mariadb
    repository: https://charts.bitnami.com
    version: 7.x.x
    import-values:
      - image
```

这允许在父图中如下引用子图中`exports.image`下的默认值：

```
registry: 'my-registry.io'
name: learnhelm/my-image
tag: latest
```

请注意，这已经删除了`image`映射，并且只留下了其下面的键值对。如果您不希望发生这种情况，`import-values`字段可以通过遵循所谓的`child-parent`格式保留`image`映射。这允许图表开发人员指定应从子图导入的值，并提供它们在父图中应被称为的名称。`child-parent`格式允许在不需要子图中的`exports`块中的值的情况下完成此操作。以下`dependencies`块演示了这种情况的示例：

```
dependencies:
  - name: mariadb
    repository: https://charts.bitnami.com
    version: 7.x.x
    import-values:
      - child: image
        parent: image
```

此示例将子图中`image`块下的每个值导入到父图中的`image`块下。

重要提示：

使用`import-values`字段导入的值不能在父图中被覆盖。如果您需要覆盖子图中的值，您不应该使用`import-values`字段，而应该通过在每个值的前缀中加上子图的名称来覆盖所需的值。

在本节中，我们介绍了如何在`Chart.yaml`文件中管理依赖关系。现在，让我们了解一下如何在 Helm 图中定义生命周期管理钩子。

# 生命周期管理

Helm 图表及其相关发布的主要优势之一是能够在 Kubernetes 上管理复杂的应用程序。发布在其生命周期中经历多个阶段。为了提供关于发布生命周期的额外管理能力，Helm 提供了一个`hooks`机制，以便可以在发布周期的不同时间点执行操作。在本节中，我们将探讨发布生命周期的不同阶段，并介绍如何使用`hooks`来提供与发布以及整个 Kubernetes 环境的交互能力。

在*第三章*中，*安装您的第一个 Helm 图表*，我们遇到了涵盖 Helm 发布整个生命周期的几个阶段，包括安装、升级、删除和回滚。鉴于 Helm 图表可能很复杂，因为它们管理将部署到 Kubernetes 的一个或多个应用程序，通常需要执行除了部署资源之外的其他操作。这些操作可能包括以下内容：

+   完成应用程序所需的先决条件，例如管理证书和密钥

+   作为图表升级的一部分进行数据库管理，以执行备份或恢复

+   在删除图表之前清理资产

潜在选项列表可能很长，首先了解 Helm 挂钩的基础知识以及它们何时可以执行是很重要的，我们将在下一节中描述。

## Helm 挂钩的基础知识

挂钩在发布的生命周期中的指定时间点执行一次操作。与 Helm 中的大多数功能一样，挂钩被实现为另一个 Kubernetes 资源，更具体地说是在一个容器中。虽然 Kubernetes 中的大多数工作负载都设计为长时间运行的进程，比如提供 API 请求的应用程序，但工作负载也可以由一个单独的任务或一组任务组成，使用脚本执行，一旦完成就指示成功或失败。

在 Kubernetes 环境中通常用于创建短暂任务的两个选项是使用裸**pod**或**job**。裸 pod 是一个运行直到完成然后终止的 pod，但如果底层节点失败，它将不会被重新调度。因此，可能更倾向于将生命周期钩子作为作业运行，如果节点失败或不可用，则重新调度钩子。

由于钩子只是被定义为 Kubernetes 资源，它们也被放置在`templates/`文件夹中，并用 helm.sh/hook 注释进行标注。这个注释的指定确保它们不会与标准处理过程中应用于 Kubernetes 环境的其他资源一起渲染。相反，它们根据 helm.sh/hook 注释中指定的值进行渲染和应用，该值确定了它应该在 Helm 发布生命周期的 Kubernetes 中何时执行。

以下是如何将钩子定义为作业的示例：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: helm-auditing
  annotations:
    'helm.sh/hook': pre-install,post-install
spec:
  template:
    metadata:
      name: helm-auditing
    spec:
      restartPolicy: Never
      containers:
      - name: helm-auditing
        command: ["/bin/sh", "-c", "echo Hook Executed at $(date)"]
        image: alpine
```

这个微不足道的例子在休眠 10 秒之前打印出容器中的当前日期和时间。Helm 在安装图表之前和之后执行这个钩子，如'helm.sh/hook'注释的值所示。这种类型的钩子的一个用例是连接到一个审计系统，跟踪应用程序在 Kubernetes 环境中的安装。类似的钩子可以在安装完成后添加，以跟踪完成图表安装过程所花费的总时间。

现在我们已经解释了 Helm 钩子的基础知识，让我们讨论如何在 Helm 图表中定义钩子。

## 钩子执行

正如你在前一节的`job`钩子中看到的，`helm.sh/hook`注释的值是`pre-install`。`pre-install`是 Helm 图表生命周期中可以执行钩子的时间点之一。

以下表格表示了`helm.sh/hook`注释的可用选项，指示钩子的执行时间。每个钩子的描述都引用了官方 Helm 文档，可以在 https://helm.sh/docs/topics/charts_hooks/#the-available-hooks 找到。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/041.jpg)

`helm.sh/hook`注释可以包含多个值，表示在图表发布周期内的不同时间点执行相同的资源。例如，为了在图表安装之前和之后执行钩子，可以在 pod 或作业上定义以下注释：

```
annotations:
  'helm.sh/hook': pre-install,post-install
```

了解钩子何时以及如何执行是有用的，以确定需要选择的图表生命周期中的期望阶段。如前面的示例所述，当钩子被指定在执行`helm install`命令的`pre-install`和`post-install`部分时，将发生以下操作：

1.  用户安装 Helm 图表（例如通过运行`helm install bitnami/wordpress --version 8.1.0`）。

1.  调用 Helm API。

1.  在 Kubernetes 环境中加载`crds/`文件夹中的 CRD。

1.  执行图表模板的验证并呈现资源。

1.  预安装钩子按权重排序，然后呈现并加载到 Kubernetes 中。

1.  Helm 等待直到钩子准备就绪。

1.  模板资源被呈现并应用于 Kubernetes 环境。

1.  执行`post-install`钩子。

1.  Helm 等待直到`post-install`钩子完成。

1.  返回`helm install`命令的结果。

了解 Helm 钩子执行的基础知识后，让我们来讨论一些关于 Helm 钩子的更高级主题。

## 高级钩子概念

虽然将标准 Helm 模板资源转换为钩子所需的工作量很小，但还有其他选项可帮助执行图表和删除资源。

在 Helm 图表的生命周期中执行的钩子数量没有限制，可能存在多个钩子为同一生命周期阶段配置的情况。当出现这种情况时，默认情况下，钩子按名称按字母顺序排序。但是，您可以通过使用`helm.sh/weight`注释指定每个钩子的权重来定义顺序。权重按升序排序，但如果多个钩子包含相同的权重值，则使用默认逻辑按名称按字母顺序排序。

虽然钩子为生命周期管理提供了有用的机制，但应该记住，与常规模板资源不同，钩子在调用`helm uninstall`命令时不会随图表的其余部分一起删除，因为它们不受 Helm 跟踪或管理。相反，可以采用一些策略来在发布的生命周期中删除钩子，例如配置删除策略和设置作业的 TTL。

首先，可以在与钩子相关的 pod 或 job 上指定`helm.sh/hook-delete-policy`注释。此注释确定 Helm 应何时对 Kubernetes 中的资源进行删除。有以下选项（描述参考 Helm 文档，可在 https://helm.sh/docs/topics/charts_hooks/#hook-deletion-policies 找到）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/10.jpg)

此外，Kubernetes 提供了定义**生存时间**（**TTL**）机制的选项，以限制资源在完成后保留的时间量，使用作业的`ttlSecondsAfterFinished`属性，如下所示：

```
apiVersion: batch/v1
kind: Job
metadata:
  name: ttl-job
  annotations:
    'helm.sh/hook': post-install
spec:
  ttlSecondsAfterFinished: 60
```

在此示例中，资源在完成或失败后的 60 秒内被删除。

发布生命周期的最后阶段是删除，尽管在调用`helm uninstall`命令时会删除标准图表模板，但您可能希望保留某些资源，以便 Helm 不对其采取行动。一个常见的用例是，在发布生命周期的开始时通过`PersistentVolumeClaim`命令创建新的持久卷，但在结束时不应与其他资源一起删除，以便保留卷的数据。通过使用`helm.sh/resource-policy`注释启用此选项，如下所示：

```
'helm.sh/resource-policy': keep
```

Helm 将不再在执行`helm uninstall`命令期间考虑删除此资源。需要注意的是，当资源不再受管理时，一旦其余资源被删除，它就变成了孤立的。如果使用`helm install`命令，可能会导致资源命名冲突，因为之前未删除的现有资源。可以使用`kubectl delete`命令手动删除孤立的资源。

本节讨论了如何编写钩子和自动化来管理图表的生命周期。在下一节中，我们将讨论如何适当地记录 Helm 图表，以确保其用户拥有流畅的体验。

# 记录 Helm 图表

与用户交互的任何其他软件一样，Helm 图表应该有适当的文档，以便用户知道如何与其交互。Helm 图表结构支持用于记录用法的`README.md`文件，用于覆盖用法和分发权利的`LICENSE`文件，以及用于在图表安装期间生成用法说明的`templates/NOTES.txt`文件。

README.md 文件

**README**是软件开发中常用的文件，用于描述产品的安装、使用和其他细节。 Helm 图表的 README 文件通常包含以下细节：

+   **先决条件**：先决条件的一个常见示例是在安装图表之前在 Kubernetes 集群中创建一个`secret`或一组 secrets，以便挂载到 Kubernetes 部署中。 用户可以通过参考 README 文件来了解这一要求。

+   **值**：图表通常包含许多不同的值，每个值都应在`README`文件中以表格形式描述。 表格应指定值的名称，其描述或功能以及其默认值。 您还可能发现有帮助的是指示该值是否需要在安装或升级期间提供。

+   **特定于应用程序的信息**：一旦使用 Helm 图表安装了应用程序，您可能需要有关应用程序本身的其他信息，例如如何访问它或应用程序的功能。 这些细节可以在`README`文件中提供。

Helm READMEs 使用**Markdown**格式语言编写。 Markdown 通常用于 GitHub 项目和开源软件，并且是一种可以以优雅格式显示的文本的简便编码方式。 可以在**Markdown Guide**网站上进一步探索 Markdown，位于 https://www.markdownguide.org/。

## 许可证文件

除了`README`文件中包含的技术说明之外，图表维护者可能发现有必要包含一个许可证，以指示用户在图表使用和分发方面的权限。 这些细节可以在图表目录下的名为`LICENSE`的文件中组成。

`LICENSE`文件是一个包含软件许可证的纯文本文件。 许可证可以是自定义编写的，也可以是常用于开源软件的许可证的副本，例如 Apache 许可证 2.0 或 MIT 许可证。 理解许可证之间的区别以及使用和分发软件的合法性超出了本书的范围，但您可以开始在**选择许可证**网站（https://choosealicense.com/）上探索这些细节，该网站将帮助您选择适合您的 Helm 图表的合适许可证。

## templates/NOTES.txt 文件

与`README.md`文件类似，`templates/NOTES.txt`文件用于提供使用说明，一旦使用 Helm 安装应用程序。不同之处在于，`README.md`文件是静态的，而`NOTES.txt`文件可以使用 Go 模板动态生成。

假设 Helm 图表在其`values.yaml`文件中配置了以下值：

```
## serviceType can be set to NodePort or LoadBalancer
serviceType: NodePort
```

根据设置的服务类型，访问应用程序的说明将有所不同。如果服务是`NodePort`服务，则可以使用在每个 Kubernetes 节点上设置的特定端口号来访问。如果服务设置为`LoadBalancer`，则将使用在创建服务时自动配置的负载均衡器的 URL 来访问应用程序。根据所使用的服务类型访问应用程序的方式可能对经验不足的 Kubernetes 用户来说有些困难，因此该图表的维护者应该在`templates/`目录下提供一个`NOTES.txt`文件，其中提供了关于如何访问应用程序的说明。

以下示例说明了如何使用`templates/NOTES.txt`文件来实现此目的：

```
Follow these instructions to access your application.
{{- if eq .Values.serviceType 'NodePort' }}
export NODE_PORT=$(kubectl get --namespace {{ .Release.Namespace }} -o jsonpath='{.spec.ports[0].nodePort}' services {{.Release.Name }})
export NODE_IP=$(kubectl get nodes --namespace {{ .Release.Namespace }} -o jsonpath='{.items[0].status.addresses[0].address}')
echo "URL: http://$NODE_IP:$NODE_PORT"
{{- else }}
export SERVICE_IP=$(kubectl get svc --namespace {{ .Release.Name }} wordpress --template '{{ range (index .status.loadBalancer.ingress 0) }}{{.}}{{ end }}')
echo "URL: http://$SERVICE_IP"
{{- end }}
```

此文件将在应用程序的安装、升级和回滚阶段生成和显示，并且可以通过运行`helm get notes`命令来调用。通过提供此文件，用户将更好地了解如何使用应用程序。

到目前为止，在本章中，我们已经描述了 Helm 图表的大部分组成部分，除了实际的打包，这样可以使图表易于分发。这个概念将在下一节中描述。

# 打包 Helm 图表

虽然 Helm 图表遵循通用的文件结构，但它们应该打包以便于分发。图表以`tgz`存档的形式打包。虽然可以使用`tar` bash 实用程序或存档管理器手动创建这些存档，但 Helm 提供了`helm package`命令来简化此任务。`helm package`命令的语法如下所示：

```
$ helm package [CHART_NAME] [...] [flags]
```

`helm package`命令针对本地图表目录运行。如果此命令成功，它将生成一个具有以下文件格式的`tgz`存档：

```
$CHART_NAME-$CHART_VERSION.tgz
```

存档然后可以通过推送到图表存储库来分发，这是在*第五章*中进一步探讨的任务，*构建您的第一个 Helm 图表*。

`helm package`命令包括图表目录下的每个文件。虽然这通常是首选行为，但如果目录中包含对 Helm 不必要的文件，则可能并非总是如此。一个常见的例子是`.git/`目录，它存在于由**Git SCM**管理的项目中。如果将此文件打包到图表的`tgz`存档中，它将毫无意义，只会增加存档的大小。Helm 支持一个名为`.helmignore`的文件，可用于从 Helm 存档中省略某些文件和文件夹。以下是一个示例`.helmignore`文件：

```
# Ignore git directories and files
.git/
.gitignore
```

上述文件指示，如果`.git/`目录或`.gitignore`文件出现在图表目录中，它们将被`helm package`命令忽略，这意味着它们不会出现在生成的`tgz`存档中。在此文件中以井号符号(`#`)开头的行用作注释。如果您的图表目录包含对图表的整体功能不必要的文件和文件夹，请确保在 Helm 图表中包含一个`.helmignore`文件。

# 摘要

Helm 图表是一组文件，主要以 YAML 格式编写，遵循特定的文件结构。`Chart.yaml`文件用于设置图表元数据并声明依赖关系。`templates/`目录用于包含 Kubernetes YAML 资源，这些资源是 Go 模板化的，允许它们动态生成。在`templates/`目录下定义的 Kubernetes 资源还可以包含某些钩子，用于配置应用程序生命周期中的各个阶段。为了向用户提供文档，图表可以包含`README.md`和`templates/NOTES.txt`文件，还可以包含`LICENSE`文件以声明图表的使用和分发权利。最后，图表可以包含一个`.helmignore`文件，用于从最终打包的产品中省略声明的文件。

在本章中，您了解了 Helm 图表的结构以及如何配置关键的图表组件。有了本章的知识，您现在了解了如何从头开始编写您的第一个 Helm 图表的基本概念，我们将在*第五章*中进行，*构建您的第一个 Helm 图表*。

# 进一步阅读

要了解有关创建 Helm 图表的基础知识，请参阅 Helm 文档中的 Chart 模板指南页面，网址为 https://helm.sh/docs/chart_template_guide/。https://helm.sh/docs/topics/charts/中的“图表”部分还描述了本章中讨论的许多主题，包括图表文件结构、依赖关系和`Chart.yaml`文件。

# 问题

1.  在 Kubernetes 和 Helm 中最常用的文件格式是什么？

1.  `Chart.yaml`文件中的三个必填字段是什么？

1.  如何引用或覆盖图表依赖项的值？

1.  想象一下，您想要对使用 Helm 部署的数据库进行数据快照。在将数据库升级到更新版本之前，您可以采取什么措施来确保在升级数据库之前进行数据“快照”？

1.  作为图表开发人员，您可以创建哪些文件来为最终用户提供文档并简化图表安装过程？

1.  您可以利用哪种 Helm 模板构造来生成重复的 YAML 部分？

1.  `Chart.yaml`文件与`Chart.lock`文件有什么不同？

1.  什么是将资源定义为钩子的注释的名称？

1.  图表模板中的函数和管道的目的是什么？可以使用哪些常见函数？


# 第五章：构建您的第一个 Helm 图表

在上一章中，您了解了组成 Helm 图表的各个方面。现在，是时候将这些知识付诸实践，构建一个 Helm 图表了。学会构建 Helm 图表将使您能够以简单的方式打包复杂的 Kubernetes 应用程序。

在本章中，您将学习如何构建一个 Helm 图表，用于部署`guestbook`应用程序，这是 Kubernetes 社区中广泛使用的快速入门应用程序。通过遵循 Kubernetes 和 Helm 图表开发的最佳实践，构建此图表将提供一个编写良好且易于维护的自动化部分。在开发此图表的过程中，您将学习许多不同的技能，可以应用于构建自己的 Helm 图表。在本章结束时，您将学习如何打包您的 Helm 图表并将其部署到图表存储库，以便最终用户可以轻松访问。

本章涵盖的主要主题如下：

+   了解 Guestbook 应用程序

+   创建 Guestbook Helm 图表

+   改进 Guestbook Helm 图表

+   将 Guestbook 图表发布到图表存储库

# 技术要求

本章需要以下技术：

+   `minikube`

+   `kubectl`

+   `helm`

除了前面提到的工具之外，您还会发现本书的 GitHub 存储库位于[`github.com/PacktPublishing/-Learn-Helm`](https://github.com/PacktPublishing/-Learn-Helm)。我们将引用本章中包含的`helm-charts/charts/guestbook`文件夹。

建议您拥有自己的 GitHub 帐户，以便完成本章的最后一节*创建图表存储库*。有关如何创建您自己的帐户的说明将在该部分提供。

# 了解 Guestbook 应用程序

在本章中，您将创建一个 Helm 图表，用于部署 Kubernetes 社区提供的 Guestbook 教程应用程序。该应用程序在 Kubernetes 文档的以下页面中介绍：[`kubernetes.io/docs/tutorials/stateless-application/guestbook/`](https://kubernetes.io/docs/tutorials/stateless-application/guestbook/)

Guestbook 应用程序是一个简单的**PHP：超文本预处理器**（**PHP**）前端，旨在将消息持久保存到 Redis 后端。前端包括对话框和**提交**按钮，如下截图所示：

![图 5.1：Guestbook PHP 前端](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.1.jpg)

图 5.1：Guestbook PHP 前端

用户可以按照以下步骤与该应用程序进行交互：

1.  在**消息**对话框中输入一条消息。

1.  单击**提交**按钮。

1.  当单击**提交**按钮时，消息将被保存到 Redis 数据库中。

Redis 是一个内存中的键值数据存储，本章中将被用于数据复制的集群。该集群将包括一个主节点，Guestbook 前端将向其写入数据。一旦写入，主节点将在多个从节点之间复制数据，Guestbook 前端将从中读取。

以下图描述了 Guestbook 前端与 Redis 后端的交互方式：

![图 5.2：Guestbook 前端和 Redis 交互](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.2.jpg)

图 5.2：Guestbook 前端和 Redis 交互

在对 Guestbook 前端和 Redis 后端的交互有了基本了解之后，让我们设置一个 Kubernetes 环境来开始开发 Helm 图表。在开始之前，让我们首先启动 minikube 并为本章创建一个专用的命名空间。

# 设置环境

为了看到您的图表运行情况，您需要按照以下步骤创建您的 minikube 环境：

1.  通过运行`minikube start`命令来启动 minikube，如下所示：

```
$ minikube start
```

1.  创建一个名为`chapter5`的新命名空间，如下所示：

```
$ kubectl create namespace chapter5
```

在部署 Guestbook 图表时，我们将使用这个命名空间。现在环境已经准备好，让我们开始编写图表。

# 创建 Guestbook Helm 图表

在本节中，我们将创建一个 Helm 图表来部署 Guestbook 应用程序。最终的图表已经发布在 Packt 存储库的`helm-charts/charts/guestbook`文件夹下。随时参考这个位置，以便您可以跟随示例。

我们将首先搭建 Guestbook Helm 图表，以创建图表的初始文件结构。

## 搭建初始文件结构

正如您可能还记得的*第四章*，*理解 Helm 图表*，Helm 图表必须遵循特定的文件结构才能被视为有效。换句话说，一个图表必须包含以下必需文件：

+   `Chart.yaml`：用于定义图表元数据

+   `values.yaml`：用于定义默认图表值

+   `templates/`：用于定义图表模板和要创建的 Kubernetes 资源

我们在*第四章*，*理解 Helm 图表*中提供了图表可能包含的每个文件的列表，但前面提到的三个文件是开始开发新图表所必需的文件。虽然这三个文件可以从头开始创建，但 Helm 提供了`helm create`命令，可以更快地搭建一个新的图表。除了创建之前列出的文件外，`helm create`命令还会生成许多不同的样板模板，可以更快地编写您的 Helm 图表。让我们使用这个命令来搭建一个名为`guestbook`的新 Helm 图表。

`helm create`命令将 Helm 图表的名称（`guestbook`）作为参数。在本地命令行上运行以下命令来搭建这个图表：

```
$ helm create guestbook
```

运行此命令后，您将在您的机器上看到一个名为`guestbook/`的新目录。这是包含您 Helm 图表的目录。在目录中，您将看到以下四个文件：

+   `charts/`

+   `Chart.yaml`

+   `templates/`

+   `values.yaml`

正如你所看到的，`helm create`命令创建了一个`charts/`目录，除了必需的`Chart.yaml`、`values.yaml`和`templates/`文件。`charts/`目录目前是空的，但以后当我们声明一个图表依赖时，它将自动填充。您可能还注意到其他提到的文件已经自动填充了默认设置。在本章的开发`guestbook`图表过程中，我们将利用许多这些默认设置。

如果您探索`templates/`目录下的内容，您会发现许多不同的模板资源已经默认包含在内。这些资源将节省创建这些资源所需的时间。虽然生成了许多有用的模板，我们将删除`templates/tests/`文件夹。这个文件夹用于包含您 Helm 图表的测试，但我们将专注于在*第六章*，*测试 Helm 图表*中编写您自己的测试。运行以下命令来删除`templates/tests/`文件夹：

```
$ rm -rf guestbook/templates/tests
```

现在`guestbook`图表已经被搭建好了，让我们继续评估生成的`Chart.yaml`文件。

## 评估图表定义

图定义，或`Chart.yaml`文件，用于包含 Helm 图的元数据。我们在*第四章*中讨论了`Chart.yaml`文件的每个可能选项，*了解 Helm 图*，但让我们回顾一下典型图定义中包含的一些主要设置，如下所示：

+   `apiVersion`：设置为`v1`或`v2`（`v2`是 Helm 3 的首选选项）

+   `version`：Helm 图的版本。这应该是符合**语义化版本规范**（**SemVer**）的版本。

+   `appVersion`：Helm 图部署的应用程序的版本

+   `name`：Helm 图的名称

+   `description`：Helm 图的简要描述及其设计部署的内容

+   `type`：设置为`application`或`library`。`Application`图用于部署特定应用程序。`Library`图包含一组辅助函数（也称为“命名模板”），可在其他图中使用，以减少样板文件。

+   `dependencies`：Helm 图依赖的图列表

如果你观察你的脚手架`Chart.yaml`文件，你会注意到每个字段（除了 dependencies）已经被设置。这个文件可以在以下截图中看到：

![图 5.3：脚手架 Chart.yaml 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.3.jpg)

图 5.3：脚手架 Chart.yaml 文件

我们暂时将文件中包含的每个设置保持为默认值（尽管如果你愿意，可以随意编写更有创意的描述）。在本章后面，当这些默认值变得相关时，我们将更新其中的一些默认值。

默认图定义中未包含的另一个设置是`dependencies`。我们将在下一节中更详细地讨论这一点，其中将添加一个 Redis 依赖项，以简化开发工作。

## 添加 Redis 图依赖

正如在*了解留言板应用程序*部分提到的，这个 Helm 图必须能够部署一个 Redis 数据库，用来保存应用程序的状态。如果你完全从头开始创建这个图，你需要对 Redis 的工作原理和如何正确部署到 Kubernetes 有适当的了解。你还需要创建相应的图模板来部署 Redis。

或者，通过包含已包含逻辑和所需图表模板的 Redis 依赖项，您可以大大减少创建`guestbook` Helm 图表所涉及的工作量。让我们通过添加 Redis 依赖项来修改生成的`Chart.yaml`文件，以简化图表开发。

添加 Redis 图表依赖的过程可以通过以下步骤完成：

1.  通过运行以下命令在 Helm Hub 存储库中搜索 Redis 图表：

```
$ helm search hub redis
```

1.  将显示的图表之一是 Bitnami 的 Redis 图表。这是我们将用作依赖项的图表。如果您尚未在*第三章*中添加`bitnami`图表存储库，请使用`helm add repo`命令立即添加此图表存储库。请注意，存储库**统一资源定位符**（**URL**）是从 Helm Hub 存储库中 Redis 图表的页面中检索的。代码可以在以下片段中看到：

```
$ helm add repo bitnami https://charts.bitnami.com
```

1.  确定您想要使用的 Redis 图表的版本。可以通过运行以下命令找到版本号列表：

```
$ helm search repo redis --versions
NAME                        	CHART VERSION	APP VERSION
bitnami/redis               	10.5.14       	5.0.8
bitnami/redis               	10.5.13       	5.0.8
bitnami/redis               	10.5.12       	5.0.8
bitnami/redis               	10.5.11       	5.0.8
```

您必须选择的版本是图表版本，而不是应用程序版本。应用程序版本仅描述 Redis 版本，而图表版本描述实际 Helm 图表的版本。

依赖项允许您选择特定的图表版本，或者使用诸如`10.5.x`之类的通配符。使用通配符可以轻松地使您的图表与匹配该通配符的最新 Redis 版本保持更新（在本例中，该版本为`10.5.14`）。在本例中，我们将使用版本`10.5.x`。

1.  将`dependencies`字段添加到`Chart.yaml`文件中。对于`guestbook`图表，我们将使用以下最低要求字段配置此字段（其他字段在*第四章*，*了解 Helm 图表*中讨论）：

`name`：依赖图的名称

`version`：依赖图的版本

`repository`：依赖图的存储库 URL

将以下**YAML 不是标记语言**（**YAML**）代码添加到您的`Chart.yaml`文件的末尾，提供您已收集的有关 Redis 图表的信息以配置依赖项的设置：

```
dependencies:
  - name: redis
    version: 10.5.x
    repository: https://charts.bitnami.com
```

添加依赖项后，您的完整`Chart.yaml`文件应如下所示（为简洁起见，已删除注释和空行）：

```
apiVersion: v2
name: guestbook
description: A Helm chart for Kubernetes
type: application
version: 0.1.0
appVersion: 1.16.0
dependencies:
  - name: redis
    version: 10.5.x
    repository: https://charts.bitnami.com
```

该文件也可以在 P[ackt repository at https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/g](https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/Chart.yaml)uestbook/Chart.yaml 中进行查看（请注意，版本和`appVersion`字段可能不同，因为我们将在本章后面修改这些字段）。

现在您的依赖已经添加到图表定义中，让我们下载这个依赖，以确保它已经正确配置。

### 下载 Redis 图表依赖

首次下载依赖时，应使用`helm dependency update`命令。此命令将下载您的依赖到`charts/`目录，并将生成`Chart.lock`文件，该文件指定了已下载的图表的元数据。

运行`helm dependency update`命令来下载您的 Redis 依赖。该命令以 Helm 图表的位置作为参数，并可以在以下代码片段中看到：

```
$ helm dependency update guestbook
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the 'bitnami' chart repository
Update Complete.  Happy Helming!
Saving 1 charts
Downloading redis from repo https://charts.bitnami.com
Deleting outdated charts
```

您可以通过确保 Redis 图表出现在`charts/`文件夹下来验证下载是否成功，如下所示：

```
$ ls guestbook/charts
redis-10.5.14.tgz
```

现在 Redis 依赖已经包含，让我们继续修改`values.yaml`文件。在这里，我们将覆盖特定于配置 Redis 以及 Guestbook 前端应用程序的值。

## 修改 values.yaml 文件

Helm chart 的`values.yaml`文件用于提供一组默认参数，这些参数在整个图表模板中被引用。当用户与 Helm 图表交互时，他们可以使用`--set`或`--values`标志覆盖这些默认值。除了提供一组默认参数外，一个写得好的 Helm 图表应该是自说明的，包含每个值的直观名称和解释难以实现的值的注释。编写一个自说明的`value.yaml`文件允许用户和维护者简单地参考这个文件，以便了解图表的值。

`helm create`命令生成一个值文件，其中包含许多在 Helm 图表开发中常用的样板值。让我们通过在文件末尾添加一些额外的值来完成配置 Redis 依赖。之后，我们将专注于修改一些样板值，以配置 Guestbook 前端资源。

### 添加值以配置 Redis 图表

虽然添加依赖项可以防止您需要创建其图表模板，但您可能仍然需要覆盖一些值以对其进行配置。在这种情况下，需要覆盖一些 Redis 图表的值，以使其能够与`guestbook`图表的其余部分无缝配合。

让我们首先了解一下 Redis 图表的值。这可以通过对下载的 Redis 图表运行`helm show values`命令来完成，如下所示：

```
$ helm show values charts/redis-10.5.14.tgz
```

请确保修改命令以匹配您下载的 Redis 图表版本。显示值列表后，让我们识别需要被覆盖的值，如下所示：

1.  Redis 图表中需要被覆盖的第一个值是`fullnameOverride`。此值显示在`helm show values`输出中，如下所示：

```
## String to fully override redis.fullname template
##
# fullnameOverride:
```

图表通常在一个名为`$CHART_NAME.fullname`的命名模板中使用这个值，以便轻松生成它们的 Kubernetes 资源名称。当设置了`fullnameOverride`时，命名模板将评估为这个值。否则，此模板的结果将基于`.Release.Name`对象，或者安装时提供的 Helm 发布的名称。

Redis 依赖项使用`redis.fullname`模板来帮助设置 Redis 主和 Redis 从服务的名称。

以下片段显示了在 Redis 图表中生成 Redis 主服务名称的示例：

```
name: {{ template 'redis.fullname' . }}-master
```

Guestbook 应用程序需要将 Redis 服务命名为`redis-master`和`redis-slave`。因此，`fullnameOverride`值应设置为`redis`。

如果您有兴趣了解`redis.fullname`模板的工作原理以及它在整个 Redis 图表中的应用方式，您可以在`charts/`文件夹下解压 Redis 依赖项。在该文件夹中，您将在`templates/_helpers.tpl`文件中找到`redis.fullname`模板，并注意其在每个 YAML 模板中的调用。 （事实证明，您生成的`guestbook`图表中也包含一个类似的模板在`_helpers.tpl`文件中，但一般来说，最好参考依赖项的资源，以防其维护者定制了模板。）

如果您有兴趣了解 Guestbook 应用程序的工作原理，可以在 GitHub 上找到源代码。以下文件定义了所需的 Redis 服务名称：

https://github.com/kubernetes/examples/blob/master/guestbook/php-redis/guestbook.php

1.  需要从 Redis 图表中覆盖的下一个值是`usePassword`。以下代码片段显示了`helm show values`输出中这个值的样子：

```
## Use password authentication
usePassword: true
```

Guestbook 应用程序已经编写为无需身份验证即可访问 Redis 数据库，因此我们将希望将此值设置为`false`。

1.  我们需要覆盖的最后一个值是`configmap`。以下是`helm show values`输出中此值的样子：

```
## Redis config file
## ref: https://redis.io/topics/config
##
configmap: |-
  # Enable AOF https://redis.io/topics/persistence#append-only-file
  appendonly yes
  # Disable RDB persistence, AOF persistence already enabled.
  save ''
```

默认的`configmap`值将启用 Redis 可以使用的两种持久性类型，**追加日志文件**（**AOF**）和**Redis 数据库文件**（**RDF**）持久性。Redis 中的 AOF 持久性通过将新数据条目添加到类似于更改日志的文件中来提供更改历史。RDF 持久性通过在一定间隔内将数据复制到文件中，以创建数据快照。

在本章后面，我们将创建简单的生命周期钩子，允许用户将 Redis 数据库备份和恢复到先前的快照。因为只有 RDB 持久性与快照文件一起工作，我们将覆盖`configmap`值以读取`appendonly no`，这将禁用 AOF 持久性。

识别每个 Redis 值后，将这些值添加到图表的`values.yaml`文件的末尾，如下面的代码块所示：

```
redis:
  # Override the redis.fullname template
  fullnameOverride: redis
  # Enable unauthenticated access to Redis
  usePassword: false
  # Disable AOF persistence
  configmap: |-
    appendonly no
```

请记住*第四章**,* *理解 Helm 图表*，从图表依赖中覆盖的值必须在该图表名称下进行范围限定。这就是为什么每个这些值将被添加到`redis:`段下面。

您可以通过参考位于 https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/values.yaml 的 Packt 存储库中的`values.yaml`文件，检查是否正确配置了 Redis 值。

重要提示

与 Redis 无关的一些值可能与您的`values.yaml`文件不同，因为我们将在下一节中修改这些值。

配置了 Redis 依赖项的值后，让我们继续修改`helm create`生成的默认值，以部署 Guestbook 前端。

### 修改值以部署 Guestbook 前端

当您在本章开头运行`helm create`命令时，它创建的一些项目是`templates/`目录下的默认模板和`values.yaml`文件中的默认值。

以下是创建的默认模板列表：

+   `deployment.yaml`：用于将 Guestbook 应用程序部署到 Kubernetes。

+   `ingress.yaml`：提供了一种从 Kubernetes 集群外部访问 Guestbook 应用程序的选项。

+   `serviceaccount.yaml`：用于为 Guestbook 应用程序创建一个专用的`serviceaccount`。

+   `service.yaml`：用于在 Guestbook 应用程序的多个实例之间进行负载平衡。还可以提供一种从 Kubernetes 集群外部访问 Guestbook 应用程序的选项。

+   _helpers.tp：提供了一组在 Helm 图表中广泛使用的常见模板。

+   `NOTES.txt`：提供了安装后访问应用程序所使用的一组说明。

每个模板都由图表的值配置。虽然`helm create`命令为部署 Guestbook 应用程序提供了一个很好的起点，但它没有提供所需的每个默认值。为了用所需的值替换默认值，我们可以观察生成的图表模板并相应地修改它们的参数。

让我们逐步了解指示需要进行修改的模板位置。

第一个位置在`deployment.yaml`图表模板中。在该文件中，有一行指示要部署的容器映像，如下所示：

```
image: '{{ .Values.image.repository }}:{{ .Chart.AppVersion }}'
```

如您所见，image 由`image.repository`值和`AppVersion`图表设置确定。如果您查看您的`values.yaml`文件，您会看到`image.repository`值当前配置为默认部署`nginx`映像，如下所示：

```
image:
  repository: nginx
```

同样，如果您查看`Chart.yaml`文件，您会看到`AppVersion`目前设置为`1.16.0`，如下所示：

```
appVersion: 1.16.0
```

由于 Guestbook 应用程序起源于 Kubernetes 教程，您可以在 Kubernetes 文档中找到需要部署的特定映像，网址为 https://kubernetes.io/docs/tutorials/stateless-application/guestbook/#creating-the-guestbook-frontend-deployment。在文档中，您可以看到必须指定映像如下：

```
image: gcr.io/google-samples/gb-frontend:v4
```

因此，为了正确生成 image 字段，`image.repository`值必须设置为`gcr.io/google-samples/gb-frontend`，并且`AppVersion`图表设置必须设置为`v4`。

必须进行修改的第二个位置是`service.yaml`图表模板。在这个文件中，有一行确定服务类型的代码，如下所示：

```
type: {{ .Values.service.type }}
```

根据`service.type`的值，该服务将默认为`ClusterIP`服务类型，如`values.yaml`文件中所示：

```
service:
  type: ClusterIP
```

对于`guestbook`图表，我们将修改此值，以创建一个`NodePort`服务。这将允许在 minikube 环境中更容易地访问应用程序，通过在 minikube 虚拟机（VM）上暴露一个端口。连接到端口后，我们可以访问 Guestbook 前端。

请注意，虽然`helm create`生成了一个`ingress.yaml`模板，也允许访问，但在 minikube 环境中工作时，更常见的建议是使用`NodePort`服务，因为不需要附加组件或增强功能。幸运的是，生成的图表默认禁用了入口资源的创建，因此无需禁用此功能。

现在我们已经确定了需要更改的默认设置，让我们首先按照以下方式更新`values.yaml`文件：

1.  将`image.repository`值替换为`gcr.io/google-samples/gb-frontend`。整个`image:`部分现在应该如下所示：

```
image:
  repository: gcr.io/google-samples/gb-frontend
  pullPolicy: IfNotPresent
```

1.  将`service.type`值替换为`NodePort`。整个`service:`部分现在应该如下所示：

```
service:
  type: NodePort
  port: 80
```

1.  您可以通过参考 Packt 存储库中的文件来验证您的`values.yaml`文件是否已正确修改。

接下来，让我们更新`Chart.yaml`文件，以便部署正确的 Guestbook 应用程序版本，如下所示：

1.  将`appVersion`字段替换为`v4`。`appVersion`字段现在应该如下所示：

```
appVersion: v4
```

1.  您可以通过参考 Packt 存储库中的文件来验证您的`Chart.yaml`文件是否已正确修改。

现在图表已经使用正确的值和设置进行了更新，让我们通过将其部署到 minikube 环境中来看看这个图表的运行情况。

## 安装 Guestbook 图表

要安装您的`guestbook`图表，请在`guestbook/`目录之外运行以下命令：

```
$ helm install my-guestbook guestbook -n chapter5
```

如果安装成功，将显示以下消息：

```
NAME: my-guestbook
LAST DEPLOYED: Sun Apr 26 09:57:52 2020
NAMESPACE: chapter5
STATUS: deployed
REVISION: 1
NOTES:
1\. Get the application URL by running these commands:
  export NODE_PORT=$(kubectl get --namespace chapter5 -o jsonpath='{.spec.ports[0].nodePort}' services my-guestbook)
  export NODE_IP=$(kubectl get nodes --namespace chapter5 -o jsonpath='{.items[0].status.addresses[0].address}')
  echo http://$NODE_IP:$NODE_PORT
```

安装成功后，您可能会发现留言板和 Redis pods 并不立即处于“准备就绪”状态。当一个 Pod 没有准备就绪时，它还不能被访问。

您还可以通过传入`--wait`标志来强制 Helm 等待这些 Pod 准备就绪。`--wait`标志可以与`--timeout`标志一起使用，以增加 Helm 等待 Pod 准备就绪的时间（以秒为单位）。默认设置为 5 分钟，这对于这个应用程序来说已经足够了。

您可以通过检查每个 Pod 的状态来确保所有的 Pod 都已准备就绪，而不使用`--wait`标志，如下所示：

```
$ kubectl get pods -n chapter5
```

当每个 Pod 准备就绪时，您将能够观察到每个 Pod 在`READY`列下报告为`1/1`，如下所示：

![图 5.4：当每个 Pod 准备就绪时，kubectl get pods –n chapter5 的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.4.jpg)

图 5.4：当每个 Pod 准备就绪时，kubectl get pods –n chapter5 的输出

一旦 Pod 准备就绪，您可以运行发布说明中显示的命令。如果需要，可以通过运行以下代码再次显示它们：

```
$ helm get notes my-guestbook -n chapter5
NOTES:
1\. Get the application URL by running these commands:
  export NODE_PORT=$(kubectl get --namespace chapter5 -o jsonpath='{.spec.ports[0].nodePort}' services my-guestbook)
  export NODE_IP=$(kubectl get nodes --namespace chapter5 -o jsonpath='{.items[0].status.addresses[0].address}')
  echo http://$NODE_IP:$NODE_PORT
```

将留言板 URL（从`echo`命令的输出中复制并粘贴）到您的浏览器中，留言板**用户界面**（**UI**）应该显示出来，如下截图所示：

![图 5.5：留言板前端](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.5.jpg)

图 5.5：留言板前端

尝试在对话框中输入一条消息，然后单击**提交**。留言板前端将在**提交**按钮下显示消息，这表明消息已保存到 Redis 数据库，如下截图所示：

![图 5.6：留言板前端显示先前发送的消息](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.6.jpg)

图 5.6：留言板前端显示先前发送的消息

如果您能够编写一条消息并在屏幕上看到它显示出来，那么您已成功构建和部署了您的第一个 Helm 图表！如果您无法看到您的消息，那么您的 Redis 依赖项可能没有正确设置。在这种情况下，请确保您的 Redis 值已经正确配置，并且您的 Redis 依赖已经在`Chart.yaml`文件中正确声明。

当您准备好时，使用`helm uninstall`命令卸载此图表，就像这样：

```
$ helm uninstall my-guestbook -n chapter5
```

您还需要手动删除 Redis **PersistentVolumeClaims**（**PVCs**），因为 Redis 依赖于使用`StatefulSet`使数据库持久化（在删除时不会自动删除 PVCs）。

运行以下命令以删除 Redis PVCs：

```
$ kubectl delete pvc -l app=redis -n chapter5
```

在下一节中，我们将探讨改进`guestbook`图表的方法。

# 改进 Guestbook Helm 图表

在上一节中创建的图表成功部署了 Guestbook 应用程序。然而，与任何类型的软件一样，Helm 图表总是可以改进的。在本节中，我们将专注于以下两个功能，以改进`guestbook`图表：

+   生命周期钩子备份和恢复 Redis 数据库

+   输入验证以确保只提供有效的值

让我们首先专注于添加生命周期钩子。

## 创建 pre-upgrade 和 pre-rollback 生命周期钩子

在本节中，我们将创建两个生命周期钩子，如下：

1.  第一个钩子将出现在`pre-upgrade`生命周期阶段。这个阶段发生在运行`helm upgrade`命令之后，但在任何 Kubernetes 资源被修改之前。这个钩子将用于在执行升级之前对 Redis 数据库进行数据快照，确保在升级出现错误时可以备份数据库。

1.  第二个钩子将出现在`pre-rollback`生命周期阶段。这个阶段发生在运行`helm rollback`命令之后，但在任何 Kubernetes 资源被回滚之前。这个钩子将把 Redis 数据库恢复到先前的数据快照，并确保 Kubernetes 资源配置被恢复到快照被拍摄时的状态。

在本节结束时，您将更加熟悉生命周期钩子以及它们可以执行的一些强大功能。请记住，本节中创建的钩子非常简单，仅用于探索 Helm 钩子的基本功能。不建议尝试在生产环境中直接使用这些钩子。

让我们来看看如何创建`pre-upgrade`生命周期钩子。

### 创建 pre-upgrade 钩子以进行数据快照

在 Redis 中，数据快照包含在`dump.rdb`文件中。我们可以通过创建一个钩子来备份这个文件，该钩子首先在 Kubernetes 命名空间中创建一个新的 PVC。然后，该钩子可以创建一个`job`资源，将`dump.rdb`文件复制到新的`PersistentVolumeClaim`中。

虽然`helm create`命令生成了一些强大的资源模板，可以快速创建初始的`guestbook`图表，但它没有生成任何可用于此任务的钩子。因此，您可以通过以下步骤从头开始创建预升级钩子：

1.  首先，您应该创建一个新的文件夹来包含钩子模板。虽然这不是技术要求，但它有助于将钩子模板与常规图表模板分开。它还允许您按功能对钩子模板进行分组。

在您的`guestbook`文件结构中创建一个名为`templates/backup`的新文件夹，如下所示：

```
$ mkdir guestbook/templates/backup
```

1.  接下来，您应该创建两个模板，以执行备份所需的两个模板。所需的第一个模板是`PersistentVolumeClaim`模板，将用于包含复制的`dump.rdb`文件。第二个模板将是一个作业模板，用于执行复制操作。

创建两个空模板文件作为占位符，如下所示：

```
$ touch guestbook/templates/backup/persistentvolumeclaim.yaml
$ touch guestbook/templates/backup/job.yaml
```

1.  您可以通过参考 Packt 存储库来仔细检查您的工作。您的文件结构应该与 https://github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/charts/guestbook/templates/backup 中找到的结构完全相同。

1.  接下来，让我们创建`persistentvolumeclaim.yaml`模板。将下面文件的内容复制到您的`backup/persistentvolumeclaim.yaml`文件中（此文件也可以从 Packt 存储库 https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/templates/backup/persistentvolumeclaim.yaml 中复制。请注意，空格由`空格`组成，而不是制表符，符合有效的 YAML 语法。文件的内容可以在这里看到：![图 5.7：备份/persistentvolumeclaim.yaml 模板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.7.jpg)

图 5.7：备份/persistentvolumeclaim.yaml 模板

在继续之前，让我们浏览`persistentvolumeclaim.yaml`文件的一部分，以帮助理解它是如何创建的。

此文件的*第 1*行和*第 17*行由一个`if`操作组成。由于该操作封装了整个文件，这表明只有在`redis.master.persistence.enabled`值设置为`true`时，才会包括此资源。在 Redis 依赖图中，此值默认为`true`，可以使用`helm show values`命令观察到。

*第 5 行*确定新 PVC 备份的名称。其名称基于 Redis 依赖图创建的 Redis 主 PVC 的名称，即`redis-data-redis-master-0`，以便明确指出这是设计为备份的 PVC。其名称还基于修订号。因为此钩子作为预升级钩子运行，它将尝试使用正在升级的修订号。`sub`函数用于从此修订号中减去`1`，以便明确指出此 PVC 包含先前修订的数据快照。

*第 9 行*创建一个注释，将此资源声明为`pre-upgrade`钩子。*第 10 行*创建一个`helm.sh/hook-weight`注释，以确定此资源应与其他预升级钩子相比的创建顺序。权重按升序运行，因此此资源将在其他预升级资源之前创建。

1.  创建`persistentvolumeclaim.yaml`文件后，我们将创建最终的预升级模板`job.yaml`。将以下内容复制到您的`backup/job.yaml`文件中（此文件也可以从 Packt 存储库 https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/templates/backup/job.yaml 中复制）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.8.jpg)

图 5.8：备份/job.yaml 模板

让我们逐步了解`job.yaml`模板的部分内容，以了解它是如何创建的。

*第 9 行*再次定义此模板为预升级钩子。*第 11 行*将钩子权重设置为`1`，表示此资源将在其他预升级`PersistentVolumeClaim`之后创建。

第 10 行设置了一个新的注释，以确定何时应删除此作业。默认情况下，Helm 不管理钩子的创建之外的内容，这意味着当运行`helm uninstall`命令时，它们不会被删除。`helm.sh/hook-delete-policy`注释用于确定资源应该在何种条件下被删除。该作业包含`before-hook-creation`删除策略，这表明如果它已经存在于命名空间中，它将在`helm upgrade`命令期间被删除，从而允许创建一个新的作业。该作业还将具有`hook-succeeded`删除策略，如果成功运行，则将导致其被删除。

第 19 行执行`dump.rdb`文件的备份。它连接到 Redis 主服务器，保存数据库的状态，并将文件复制到备份 PVC。

第 29 行和第 32 行分别定义了 Redis 主 PVC 和备份 PVC。这些 PVC 被作业挂载，以便复制`dump.rdb`文件。

如果您已经按照前面的每个步骤进行操作，那么您已经为 Helm 图表创建了预升级钩子。让我们继续下一节，创建预回滚钩子。之后，我们将重新部署`guestbook`图表，以查看这些钩子的作用。

### 创建预回滚钩子以恢复数据库

而预升级钩子是用来从 Redis 主 PVC 复制`dump.rdb`文件到备份 PVC，`pre-rollback`钩子可以编写以执行相反的操作，将数据库恢复到先前的快照。

按照以下步骤创建预回滚钩子：

1.  创建`templates/restore`文件夹，用于包含预回滚钩子，如下所示：

```
$ mkdir guestbook/templates/restore
```

1.  接下来，创建一个空的`job.yaml`模板，用于恢复数据库，如下所示：

```
$ touch guestbook/templates/restore/job.yaml
```

1.  您可以通过引用 Packt 存储库来检查是否已创建了正确的结构[`github.com/PacktPublishing/-Learn-Helm/tree/master/helm`](https://github.com/PacktPublishing/-Learn-Helm/tree/master/helm-charts/charts/guestbook/templates/restore)-charts/charts/guestbook/templates/restore。

1.  接下来，让我们向`job.yaml`文件添加内容。将以下内容复制到您的`restore/job.yaml`文件中（此文件也可以从 Packt 存储库 https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/c](https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/templates/restore/job.yaml)harts/guestbook/templates/restore/job.yaml)中复制）：

![图 5.9：回滚/job.yaml 模板](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.9.jpg)

图 5.9：回滚/job.yaml 模板

此模板的*第 7 行*将此资源声明为`pre-rollback`钩子。

实际的数据恢复在*第 18 行*和*第 19 行*执行。*第 18 行*将`dump.rdb`文件从备份 PVC 复制到 Redis 主 PVC。复制后，*第 19 行*重新启动数据库，以便重新加载快照。用于重新启动 Redis 数据库的命令将返回失败的退出代码，因为与数据库的连接将意外终止，但可以通过在命令后添加`|| true`来解决这个问题，这将否定退出代码。

*第 29 行*定义了 Redis 主卷，*第 32 行*定义了所需的备份卷，这取决于要回滚到的修订版本。

创建了升级前和回滚前的生命周期钩子后，让我们在 minikube 环境中运行它们，看看它们的作用。

### 执行生命周期钩子

为了运行您创建的生命周期钩子，您必须首先通过运行`helm install`命令再次安装您的图表，如下所示：

```
$ helm install my-guestbook guestbook -n chapter5
```

当每个 Pod 报告`1/1` `Ready`状态时，通过遵循显示的发布说明访问您的 Guestbook 应用程序。请注意，访问应用程序的端口将与以前不同。

访问 Guestbook 前端后写一条消息。示例消息可以在以下截图中看到：

![图 5.10：安装 Guestbook 图表并输入消息后的 Guestbook 前端](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.10.jpg)

图 5.10：安装 Guestbook 图表并输入消息后的 Guestbook 前端

一旦写入消息并且其文本显示在**提交**按钮下方，运行`helm upgrade`命令触发 pre-upgrade 钩子。`helm upgrade`命令将暂时挂起，直到备份完成，并且可以在这里看到：

```
$ helm upgrade my-guestbook guestbook -n chapter5
```

当命令返回时，您应该会发现 Redis 主 PVC 以及一个新创建的 PVC，名为`redis-data-redis-master-0-backup-1`，可以在这里看到：

```
$ kubectl get pvc -n chapter5
NAME                                 STATUS
redis-data-redis-master-0            Bound
redis-data-redis-master-0-backup-1   Bound
```

此 PVC 包含一个数据快照，可用于在预回滚生命周期阶段恢复数据库。

现在，让我们继续向 Guestbook 前端添加额外的消息。您应该在**提交**按钮下看到两条消息，如下面的截图所示：

![图 5.11：运行回滚前的 Guestbook 消息](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.11.jpg)

图 5.11：运行回滚前的 Guestbook 消息

现在，运行`helm rollback`命令以恢复到第一个修订版。此命令将暂时挂起，直到恢复过程完成，并且可以在这里看到：

```
$ helm rollback my-guestbook 1 -n chapter5
```

当此命令返回时，请在浏览器中刷新您的 Guestbook 前端。您会看到您在升级后添加的消息消失，因为在进行数据备份之前它不存在，如下面的截图所示：

![图 5.12：在预回滚生命周期阶段完成后的 Guestbook 前端](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.12.jpg)

图 5.12：在预回滚生命周期阶段完成后的 Guestbook 前端

虽然这个备份和恢复场景只是一个简单的用例，但它演示了向图表添加 Helm 生命周期钩子可以提供的许多可能性之一。

重要提示

通过在相应的生命周期命令（`helm install`、`helm upgrade`、`helm rollback`或`helm uninstall`）中添加`--no-hooks`标志，可以跳过钩子。应用此命令的命令将跳过该生命周期的钩子。

现在，我们将专注于用户输入验证以及如何进一步改进 Guestbook 图表以帮助防止提供不当值。

## 添加输入验证

在使用 Kubernetes 和 Helm 时，当创建新资源时，Kubernetes **应用程序编程接口**（**API**）服务器会自动执行输入验证。这意味着如果 Helm 创建了无效的资源，API 服务器将返回错误消息，导致安装失败。尽管 Kubernetes 执行原生输入验证，但图表开发人员仍可能希望在资源到达 API 服务器之前执行验证。

让我们开始探索如何使用`guestbook` Helm 图表中的`fail`函数执行输入验证。

### 使用 fail 函数

`fail`函数用于立即失败模板渲染。这个函数可以用在用户提供了无效值的情况下。在本节中，我们将实现一个限制用户输入的示例用例。

你的`guestbook`图表的`values.yaml`文件包含一个名为`service.type`的值，用于确定应该为前端创建什么类型的服务。这个值可以在这里看到：

```
service:
  type: NodePort
```

我们将这个值默认设置为`NodePort`，但从技术上讲，也可以使用其他服务类型。假设你想将服务类型限制为只有`NodePort`和`ClusterIP`服务。这个操作可以通过使用`fail`函数来执行。

按照以下步骤来限制`guestbook`图表中的服务类型：

1.  找到`templates/service.yaml`服务模板。这个文件包含一行，根据`service.type`值设置服务类型，如下所示：

```
type: {{ .Values.service.type }}
```

我们应该首先检查`service.type`值是否等于`ClusterIP`或`NodePort`，然后再设置服务类型。这可以通过将一个变量设置为正确设置的列表来实现。然后，可以进行检查以确定`service.type`值是否包含在有效设置的列表中。如果是，那么就继续设置服务类型。否则，图表渲染应该被停止，并向用户返回错误消息，通知他们有效的`service.type`输入。

1.  复制下面的`service.yaml`文件来实现*步骤 1*中描述的逻辑。这个文件也可以从 Packt 仓库 https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/templates/service.yaml 中复制：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.13.jpg)

图 5.13：在 service.yaml 模板中实现的 service.type 验证

*第 8 行*到*第 13 行*代表了输入验证。*第 8 行*创建了一个名为`serviceTypes`的变量，它等于正确的服务类型列表。*第 9 行*到*第 13 行*代表了一个`if`操作。*第 9 行*中的`has`函数将检查`service.type`值是否包含在`serviceTypes`中。如果是，那么渲染将继续到*第 10 行*来设置服务的类型。否则，渲染将继续到*第 12 行*。*第 12 行*使用`fail`函数来停止模板渲染，并向用户显示关于有效服务类型的消息。

尝试通过提供无效的服务类型来升级你的`my-guestbook`发布（如果你已经卸载了你的发布，重新安装也可以）。为此，请运行以下命令：

```
$ helm upgrade my-guestbook . -n chapter5 --set service.type=LoadBalancer
```

如果你在前面的*步骤 2*中的更改成功了，你应该会看到类似以下的消息：

```
Error: UPGRADE FAILED: template: guestbook/templates/service.yaml:12:6: executing 'guestbook/templates/service.yaml' at <fail 'value 'service.type' must be either 'ClusterIP' or 'NodePort''>: error calling fail: value 'service.type' must be either 'ClusterIP' or 'NodePort'
```

使用`fail`验证用户输入是确保提供的值符合一定约束的好方法，但也有时候需要确保用户首先提供了某些值。这可以通过使用下一节中解释的`required`函数来实现。

### 使用`required`函数

`required`函数和`fail`一样，也用于停止模板渲染。不同之处在于，`required`函数用于确保在图表模板渲染时值不为空。

回想一下，你的图表中包含一个名为`image.repository`的值，如下所示：

```
image:
  repository: gcr.io/google-samples/gb-frontend
```

这个值用于确定将部署的镜像。考虑到这个值对 Helm 图表的重要性，我们可以用`required`函数来确保在安装图表时它始终有一个值。虽然我们目前在这个图表中提供了一个默认值，但添加`required`函数可以让你在需要确保用户始终提供自己的容器镜像时删除这个默认值。

按照以下步骤对`image.repository`值实施`required`函数：

1.  找到`templates/deployment.yaml`图表模板。该文件包含一行，根据`image.repository`的值设置容器镜像（`appName`图表设置也有助于设置容器镜像，但在这个例子中，我们只关注`image.repository`），如下所示：

```
image: '{{ .Values.image.repository }}:{{ .Chart.AppVersion }}'
```

1.  `required`函数接受以下两个参数：

+   显示错误消息，指出是否提供了该值 必须提供的值

给定这两个参数，修改`deployment.yaml`文件，使`image.repository`的值是必需的。

要添加这个验证，你可以从以下代码片段中复制，或者参考 Packt 仓库 https://github.com/PacktPublishing/-Learn-Helm/blob/master/helm-charts/charts/guestbook/templates/deployment.yaml 中的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.14.jpg)

图 5.14：使用第 28 行上所需功能的 deployment.yaml 片段

1.  尝试通过提供空的`image.repository`值来升级您的`my-guestbook`发布，如下所示：

```
$ helm upgrade my-guestbook . -n chapter5 --set image.repository=''
```

如果您的更改成功，您应该会看到类似以下的错误消息：

```
Error: UPGRADE FAILED: execution error at (guestbook/templates/deployment.yaml:28:21): value 'image.repository' is required
```

到目前为止，您已成功编写了您的第一个 Helm 图表，包括生命周期挂钩和输入验证！

在下一节中，您将学习如何使用 GitHub Pages 创建一个简单的图表存储库，该存储库可用于使您的`guestbook`图表对世界可用。

# 将 Guestbook 图表发布到图表存储库

现在您已经完成了 Guestbook 图表的开发，该图表可以发布到存储库，以便其他用户可以轻松访问。让我们首先创建图表存储库。

## 创建图表存储库

图表存储库是包含两个不同组件的服务器，如下所示：

+   Helm 图表，打包为`tgz`存档

+   一个包含存储库中包含的图表的元数据的`index.yaml`文件

基本的图表存储库要求维护者生成自己的`index.yaml`文件，而更复杂的解决方案，如 Helm 社区的`ChartMuseum`工具，在推送新图表到存储库时动态生成`index.yaml`文件。在这个例子中，我们将使用 GitHub Pages 创建一个简单的图表存储库。GitHub Pages 允许维护者从 GitHub 存储库创建一个简单的静态托管站点，该站点可用于创建一个基本的图表存储库来提供 Helm 图表。

您需要一个 GitHub 帐户来创建 GitHub Pages 图表存储库。[如果您已经有一个 Gi](https://github.com/login)tHub 帐户，您可以在 https://githu[b.com/login 登录。否则，](https://github.com/join)您可以在 https://github.com/join 创建一个新帐户。

一旦您登录 GitHub，按照[这些步骤创建](https://github.com/new)您的图表存储库：

1.  跟随 https://github.com/new 链接访问**创建新存储库**页面。

1.  为您的图表存储库提供一个名称。我们建议使用名称`Learn-Helm-Chart-Repository`。

1.  选择**使用 README 初始化此存储库**旁边的复选框。这是必需的，因为 GitHub 不允许您创建静态站点，如果它不包含任何内容。

1.  您可以将其余设置保留为默认值。请注意，为了利用 GitHub Pages，除非您拥有付费的 GitHub Pro 帐户，否则必须将隐私设置保留为**公共**。

1.  单击**创建存储库**按钮完成存储库创建过程。

1.  尽管您的存储库已创建，但在启用 GitHub Pages 之前，它无法提供 Helm 图表的服务。单击存储库内的**设置**选项卡以访问存储库设置。

1.  在**设置**页面（和**选项**选项卡）的**GitHub Pages**部分中找到它，它出现在页面底部。

1.  在**来源**下，从下拉列表中选择**主分支**选项。这将允许 GitHub 创建一个提供主分支内容的静态站点。

1.  如果您成功配置了 GitHub Pages，您将收到屏幕顶部显示的消息，上面写着**GitHub Pages 源已保存**。您还将能够看到您静态站点的 URL，如下面的示例截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.15.jpg)

图 5.15：GitHub Pages 设置和示例 URL

配置好 GitHub 存储库后，您应该将其克隆到本地计算机。按照以下步骤克隆存储库：

1.  通过选择页面顶部的**Code**选项卡导航到存储库的根目录。

1.  选择绿色的**克隆或下载**按钮。这将显示您的 GitHub 存储库的 URL。请注意，此 URL 与您的 GitHub Pages 静态站点不同。

如果需要，您可以使用以下示例截图来查找您的 GitHub 存储库 URL：

![图 5.16：单击克隆或下载按钮即可找到您的 GitHub 存储库 URL](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-helm/img/Figure_5.16.jpg)

图 5.16：单击克隆或下载按钮即可找到您的 GitHub 存储库 URL

1.  一旦您获得了存储库的`git`引用，就将存储库克隆到本地计算机。确保在运行以下命令时不在`guestbook`目录内，因为我们希望该存储库与`guestbook`图表分开。

```
$ git clone $REPOSITORY_URL
```

一旦您克隆了存储库，继续下一节将`guestbook`图表发布到您的图表存储库。

## 发布 Guestbook Helm 图表

Helm 提供了几个不同的命令来使发布 Helm 图表成为一个简单的任务。然而，在运行这些命令之前，您可能会发现需要增加您的图表的`version`字段在`Chart.yaml`文件中。对您的图表进行版本控制是发布过程的重要部分，就像其他类型的软件一样。

修改您的图表的`Chart.yaml`文件中的版本字段为 1.0.0，如下所示：

```
version: 1.0.0
```

一旦您的`guestbook`图表的版本已经增加，您可以继续将您的图表打包成一个`tgz`存档。这可以通过使用`helm package`命令来完成。从您本地`guestbook`目录的上一级运行此命令，如下所示：

```
$ helm package guestbook
```

如果成功，这将创建一个名为`guestbook-1.0.0.tgz`的文件。

重要提示

在处理包含依赖关系的图表时，`helm package`命令需要将这些依赖关系下载到`charts/`目录中，以便成功打包图表。如果您的`helm package`命令失败了，请检查您的 Redis 依赖是否已经下载到`charts/`目录中。如果没有，您可以在`helm package`中添加`--dependency-update`标志，这将在同一命令中下载依赖并打包您的 Helm 图表。

一旦您的图表被打包，通过运行以下命令将生成的`tgz`文件复制到您的 GitHub 图表仓库的克隆中：

```
$ cp guestbook-1.0.0.tgz $GITHUB_CHART_REPO_CLONE
```

当这个文件被复制后，您可以使用`helm repo index`命令为您的 Helm 仓库生成`index.yaml`文件。这个命令以您的图表仓库克隆的位置作为参数。运行以下命令来生成您的`index.yaml`文件：

```
$ helm repo index $GITHUB_CHART_REPO_CLONE
```

这个命令会悄悄地成功，但是你会在`Learn-Helm-Chart-Repository`文件夹内看到新的`index.yaml`文件。这个文件的内容提供了`guestbook`图表的元数据。如果这个仓库中还包含其他图表，它们的元数据也会出现在这个文件中。

您的 Helm 图表仓库现在应该包含`tgz`存档和`index.yaml`文件。通过使用以下`git`命令将这些文件推送到 GitHub：

```
$ git add --all
$ git commit -m 'feat: adding the guestbook helm chart'
$ git push origin master
```

您可能会被提示输入您的 GitHub 凭据。一旦提供，您的本地内容将被推送到远程仓库，您的`guestbook` Helm 图表将从 GitHub Pages 静态站点提供服务。

接下来，让我们将您的图表仓库添加到本地的 Helm 客户端中。

## 添加您的图表仓库

与其他图表存储库的过程类似，您必须首先知道您的 GitHub Pages 图表存储库的 URL，以便将其添加到本地。 此 URL 显示在“设置”选项卡中，如“创建图表存储库”部分所述。

一旦您知道您的图表存储库的 URL，您可以使用`helm repo add`命令将此存储库添加到本地，如下所示：

```
$ helm repo add learnhelm $GITHUB_PAGES_URL
```

此命令将允许您的本地 Helm 客户端与名为`learnhelm`的存储库进行交互。 您可以通过搜索您的本地配置的存储库来验证您的图表是否已发布。 可以通过运行以下命令来完成此操作：

```
$ helm search repo guestbook
```

您应该在搜索输出中找到`learnhelm/guestbook`图表。

成功发布`guestbook`图表后，让我们通过清理 minikube 环境来结束。

# 清理

您可以通过删除`chapter5`命名空间来清理环境，方法如下：

```
$ kubectl delete namespace chapter5
```

如果您已经完成工作，还可以使用`minikube stop`命令停止您的 minikube 集群。

# 摘要

在本章中，您学会了如何通过编写一个部署 Guestbook 应用程序的图表来从头开始构建 Helm 图表。 您首先创建了一个部署 Guestbook 前端和 Redis 依赖图表的图表，然后通过编写生命周期挂钩和添加输入验证来改进了此图表。 最后，通过使用 GitHub Pages 构建自己的图表存储库并将`guestbook`图表发布到此位置来结束了本章。

在下一章中，您将学习有关测试和调试 Helm 图表的策略，以帮助您进一步加强图表开发技能。

# 进一步阅读

有关 Guestbook 应用程序的其他信息，请参阅 Kubernetes 文档中的“使用 Redis 部署 PHP Guestbook 应用程序”教程，网址为 https://kubernetes.io/docs/tutorials/stateless-application/guestbook/。

要了解有关开发 Helm 图表模板的更多信息，请参考以下链接：

+   Helm 文档中的图表开发指南：https://helm.sh/docs/chart_template_guide/getting_started/

+   来自 Helm 文档的最佳实践列表：https://helm.sh/docs/topics/chart_best_practices/conventions/

+   有关图表钩子的附加信息：https://helm.sh/docs/topics/charts_hooks/

+   图表存储库的信息：https://helm.sh/docs/topics/chart_repository/

# 问题

1.  可以使用哪个命令来创建一个新的 Helm 图表脚手架？

1.  在开发`guestbook`图表时，声明 Redis 图表依赖提供了哪些关键优势？

1.  可以使用哪个注释来设置给定生命周期阶段的钩子的执行顺序？

1.  使用`fail`函数的常见用例是什么？`required`函数呢？

1.  为了将 Helm 图表发布到 GitHub Pages 图表存储库，涉及哪些 Helm 命令？

1.  图表存储库中的`index.yaml`文件的目的是什么？
